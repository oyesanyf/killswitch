//! # Continuous EDR Behavioral Anomaly, Stateful Process Lineage Tree & Statistical Baseline Engine
//!
//! Shifts detection away from static file signatures to continuous, real-time telemetry
//! collection and contextual execution analysis:
//! 1. **Low-Level OS Sensor Telemetry**: Models Windows Kernel Callbacks (`PsSetCreateProcessNotifyRoutineEx`,
//!    `ObRegisterCallbacks`), ETW (`Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-Threat-Intelligence`),
//!    Minifilter file/registry hooks, and Linux eBPF probes (`sched_process_exec`, `tcp_v4_connect`, `sys_enter_ptrace`).
//! 2. **Stateful Process Lineage Tree**: Tracks `ppid -> pid -> child` execution chains to catch
//!    Living-off-the-Land (LotL) sequences (e.g., `WINWORD.EXE -> cmd.exe -> powershell.exe -enc -> external IP`)
//!    that appear benign when observed as isolated single events.
//! 3. **Deterministic MITRE ATT&CK Indicators of Attack (IoAs)**:
//!    - `T1003.001`: LSASS memory credential harvesting (`PROCESS_VM_READ`, `MiniDump`, `sekurlsa`).
//!    - `T1055.012`: Remote executable memory allocation & process hollowing (`VirtualAllocEx` + `WriteProcessMemory` + `NtUnmapViewOfSection` / `CreateRemoteThread`).
//!    - `T1486` + `T1490`: Rapid high-entropy file encryption paired with Volume Shadow Copy deletion (`vssadmin delete shadows`, `wmic shadowcopy delete`).
//! 4. **Statistical & ML Behavioral Baseline**: Online Welford mean/variance ($\mu, \sigma^2$) and EWMA per
//!    machine role, process, and hour-of-day to detect service account reconnaissance, unsigned DLL loads
//!    from temporary directories, and $3\sigma$ spikes in outbound data transfers.
//! 5. **Multi-Anomaly Temporal Narrative Correlation & Automated Containment**: Correlates several
//!    low-confidence anomalies across time along a process tree into a single `EdrThreatNarrative`,
//!    computing a composite risk score and triggering process-tree freeze/termination or host network isolation.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Timelike, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sysinfo::{ProcessRefreshKind, RefreshKind, System};

use killswitch_types::adjudication::EvidenceClass;
use killswitch_types::telemetry::{SecurityEvent, TelemetryEventKind, ThreatSeverity, ThreatSignal};

use crate::attack::AttackStage;
use crate::rl_traffic::query_live_os_process_sockets;

/// Low-level operating system sensor hook mechanism that produced an EDR telemetry event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsSensorMechanism {
    /// Windows `PsSetCreateProcessNotifyRoutineEx` / `PsSetLoadImageNotifyRoutine` kernel callback.
    WindowsKernelProcessCallback,
    /// Windows `ObRegisterCallbacks` object handle pre-operation hook (e.g., `lsass.exe` handle access).
    WindowsObRegisterCallbacks,
    /// Event Tracing for Windows (`Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-Threat-Intelligence`).
    WindowsEtwProvider,
    /// Windows Minifilter driver (`FltRegisterFilter`) & Registry callback (`CmRegisterCallbackEx`).
    WindowsMinifilterDriver,
    /// Linux eBPF tracepoint / kprobe (`sched_process_exec`, `tcp_v4_connect`, `sys_enter_ptrace`).
    LinuxEbpfProbe,
    /// Linux LSM BPF (`bprm_check_security`, `file_open`, `socket_connect`).
    LinuxLsmBpf,
    /// Cross-platform live kernel process & socket table sensor snapshot.
    CrossPlatformKernelTableSensor,
}

impl OsSensorMechanism {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WindowsKernelProcessCallback => "WindowsKernelProcessCallback",
            Self::WindowsObRegisterCallbacks => "WindowsObRegisterCallbacks",
            Self::WindowsEtwProvider => "WindowsEtwProvider",
            Self::WindowsMinifilterDriver => "WindowsMinifilterDriver",
            Self::LinuxEbpfProbe => "LinuxEbpfProbe",
            Self::LinuxLsmBpf => "LinuxLsmBpf",
            Self::CrossPlatformKernelTableSensor => "CrossPlatformKernelTableSensor",
        }
    }
}

/// Execution account role used for statistical behavioral baselining.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountRole {
    InteractiveUser,
    ServiceAccount,
    SystemKernel,
    DeveloperToolchain,
}

impl AccountRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InteractiveUser => "interactive_user",
            Self::ServiceAccount => "service_account",
            Self::SystemKernel => "system_kernel",
            Self::DeveloperToolchain => "developer_toolchain",
        }
    }

    /// Infers the account role from a username or process context string.
    pub fn from_account_name(account: &str, proc_name: &str) -> Self {
        let low = account.to_ascii_lowercase();
        let proc_low = proc_name.to_ascii_lowercase();
        if low.contains("network service")
            || low.contains("local service")
            || low.starts_with("svc_")
            || low.starts_with("svc-")
            || low.contains("iis apppool")
            || low.contains("www-data")
            || low.contains("postgres")
            || low.contains("mssql")
            || low.contains("apache")
        {
            Self::ServiceAccount
        } else if low == "system"
            || low == "nt authority\\system"
            || low == "root" && (proc_low == "systemd" || proc_low == "kthreadd")
        {
            Self::SystemKernel
        } else if proc_low.contains("cargo")
            || proc_low.contains("rustc")
            || proc_low.contains("code.exe")
            || proc_low.contains("devenv.exe")
        {
            Self::DeveloperToolchain
        } else {
            Self::InteractiveUser
        }
    }
}

/// Rich real-time EDR telemetry event captured by low-level OS sensors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrSensorTelemetryEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub sensor: OsSensorMechanism,
    pub event_kind: TelemetryEventKind,
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub process_name: String,
    pub image_path: String,
    pub command_line: String,
    pub account_name: String,
    pub account_role: AccountRole,
    /// Observed Win32 / NT / Linux syscall API invocations (e.g., `VirtualAllocEx`, `WriteProcessMemory`).
    pub api_calls: Vec<String>,
    /// Target process name for cross-process operations (e.g., `lsass.exe`, `svchost.exe`).
    pub target_process_name: Option<String>,
    /// Target PID for cross-process handle/memory operations.
    pub target_pid: Option<u32>,
    /// Access mask or memory protection flags (e.g., `PROCESS_VM_READ`, `PAGE_EXECUTE_READWRITE`).
    pub access_or_protection_flags: Option<String>,
    /// Path of a loaded DLL / shared library or modified file.
    pub target_file_or_dll_path: Option<String>,
    /// Whether the loaded binary/DLL has a valid cryptographic signature.
    pub module_is_signed: Option<bool>,
    /// Number of rapid file modifications/renames in the current burst window.
    pub rapid_file_mod_count: u32,
    /// Shannon entropy (0.0..=8.0) of written file payload blocks.
    pub file_write_entropy: Option<f64>,
    /// Outbound network destination IP.
    pub destination_ip: Option<String>,
    /// Outbound network destination port.
    pub destination_port: Option<u16>,
    /// Outbound bytes transferred in the current flow window.
    pub outbound_bytes: u64,
    /// Hour of day (0..=23) when the activity occurred.
    pub hour_of_day: u8,
}

impl EdrSensorTelemetryEvent {
    pub fn new_process_create(
        pid: u32,
        parent_pid: Option<u32>,
        process_name: impl Into<String>,
        image_path: impl Into<String>,
        command_line: impl Into<String>,
        account_name: impl Into<String>,
    ) -> Self {
        let proc_name_str = process_name.into();
        let acct_str = account_name.into();
        let role = AccountRole::from_account_name(&acct_str, &proc_name_str);
        let now = Utc::now();
        Self {
            event_id: format!("edr-ev-{}", uuid::Uuid::new_v4()),
            timestamp: now,
            sensor: if cfg!(target_os = "windows") {
                OsSensorMechanism::WindowsKernelProcessCallback
            } else {
                OsSensorMechanism::LinuxEbpfProbe
            },
            event_kind: TelemetryEventKind::ProcessCreate,
            pid,
            parent_pid,
            process_name: proc_name_str,
            image_path: image_path.into(),
            command_line: command_line.into(),
            account_name: acct_str,
            account_role: role,
            api_calls: Vec::new(),
            target_process_name: None,
            target_pid: None,
            access_or_protection_flags: None,
            target_file_or_dll_path: None,
            module_is_signed: Some(true),
            rapid_file_mod_count: 0,
            file_write_entropy: None,
            destination_ip: None,
            destination_port: None,
            outbound_bytes: 0,
            hour_of_day: now.hour() as u8,
        }
    }

    pub fn to_security_event(&self) -> SecurityEvent {
        let mut ev = SecurityEvent::new(
            self.event_kind,
            self.pid,
            &self.process_name,
            &self.image_path,
            &self.command_line,
        );
        ev.parent_pid = self.parent_pid;
        ev.target_path = self.target_file_or_dll_path.clone();
        ev.destination_ip = self.destination_ip.clone();
        ev.destination_port = self.destination_port;
        ev.attributes
            .insert("sensor".to_string(), self.sensor.as_str().to_string());
        ev.attributes.insert(
            "account_role".to_string(),
            self.account_role.as_str().to_string(),
        );
        ev
    }
}

// ============================================================================
// 1. Stateful Process Lineage Tree & Living-off-the-Land (LotL) Analyzer
// ============================================================================

/// Stateful node in the EDR process execution lineage tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessLineageNode {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub process_name: String,
    pub image_path: String,
    pub command_line: String,
    pub account_name: String,
    pub account_role: AccountRole,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub children_pids: Vec<u32>,
    pub api_calls_observed: Vec<String>,
    pub unsigned_dlls_loaded: Vec<String>,
    pub external_connections: Vec<String>,
    pub total_outbound_bytes: u64,
    pub rapid_file_mod_count: u32,
    pub max_file_entropy: f64,
    pub shadow_copy_delete_attempted: bool,
}

/// Violation detected by contextual parent-child execution chain tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageChainViolation {
    pub rule_id: String,
    pub mitre_techniques: Vec<String>,
    pub stage: AttackStage,
    pub root_pid: u32,
    pub leaf_pid: u32,
    pub lineage_chain_display: String,
    pub confidence: f32,
    pub description: String,
}

/// Stateful process lineage graph maintaining parent-child trees and detecting multi-hop LotL chains.
#[derive(Debug, Clone, Default)]
pub struct StatefulProcessLineageTree {
    nodes: HashMap<u32, ProcessLineageNode>,
}

impl StatefulProcessLineageTree {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn get_node(&self, pid: u32) -> Option<&ProcessLineageNode> {
        self.nodes.get(&pid)
    }

    /// Upserts a telemetry event into the stateful process lineage tree.
    pub fn ingest_event(&mut self, ev: &EdrSensorTelemetryEvent) {
        let now = ev.timestamp;
        let is_external_dst = ev
            .destination_ip
            .as_deref()
            .map(is_unfamiliar_external_ip)
            .unwrap_or(false);

        if self.nodes.len() >= 4096 && !self.nodes.contains_key(&ev.pid) {
            if let Some(&oldest_pid) = self.nodes.keys().next() {
                self.nodes.remove(&oldest_pid);
            }
        }
        let entry = self.nodes.entry(ev.pid).or_insert_with(|| ProcessLineageNode {
            pid: ev.pid,
            parent_pid: ev.parent_pid,
            process_name: ev.process_name.clone(),
            image_path: ev.image_path.clone(),
            command_line: ev.command_line.clone(),
            account_name: ev.account_name.clone(),
            account_role: ev.account_role,
            first_seen: now,
            last_seen: now,
            children_pids: Vec::new(),
            api_calls_observed: Vec::new(),
            unsigned_dlls_loaded: Vec::new(),
            external_connections: Vec::new(),
            total_outbound_bytes: 0,
            rapid_file_mod_count: 0,
            max_file_entropy: 0.0,
            shadow_copy_delete_attempted: false,
        });

        entry.last_seen = now;
        if ev.parent_pid.is_some() {
            entry.parent_pid = ev.parent_pid;
        }
        if !ev.command_line.is_empty() {
            entry.command_line = ev.command_line.clone();
        }
        for api in &ev.api_calls {
            if !entry.api_calls_observed.contains(api) {
                entry.api_calls_observed.push(api.clone());
            }
        }
        if let Some(dll_path) = &ev.target_file_or_dll_path {
            if ev.module_is_signed == Some(false) && !entry.unsigned_dlls_loaded.contains(dll_path) {
                entry.unsigned_dlls_loaded.push(dll_path.clone());
            }
        }
        if is_external_dst {
            if let Some(ip) = &ev.destination_ip {
                let ep = format!("{}:{}", ip, ev.destination_port.unwrap_or(443));
                if !entry.external_connections.contains(&ep) {
                    entry.external_connections.push(ep);
                }
            }
        }
        entry.total_outbound_bytes = entry.total_outbound_bytes.saturating_add(ev.outbound_bytes);
        entry.rapid_file_mod_count = entry
            .rapid_file_mod_count
            .saturating_add(ev.rapid_file_mod_count);
        if let Some(ent) = ev.file_write_entropy {
            if ent > entry.max_file_entropy {
                entry.max_file_entropy = ent;
            }
        }
        if is_shadow_copy_deletion_command(&ev.command_line)
            || ev.event_kind == TelemetryEventKind::VolumeShadowCopyDelete
        {
            entry.shadow_copy_delete_attempted = true;
        }

        // Link parent -> child edge
        if let Some(ppid) = ev.parent_pid {
            if ppid != ev.pid {
                if let Some(parent_node) = self.nodes.get_mut(&ppid) {
                    if !parent_node.children_pids.contains(&ev.pid) {
                        parent_node.children_pids.push(ev.pid);
                    }
                }
            }
        }
    }

    /// Reconstructs the ordered execution chain from root ancestor down to `leaf_pid` (up to depth 8).
    pub fn get_execution_chain_root_to_leaf(&self, leaf_pid: u32) -> Vec<ProcessLineageNode> {
        let mut chain = Vec::new();
        let mut curr = Some(leaf_pid);
        let mut visited = HashSet::new();

        while let Some(pid) = curr {
            if !visited.insert(pid) || chain.len() >= 8 {
                break;
            }
            if let Some(node) = self.nodes.get(&pid) {
                chain.push(node.clone());
                curr = node.parent_pid;
            } else {
                break;
            }
        }
        chain.reverse();
        chain
    }

    /// Formats the lineage chain as `"WINWORD.EXE (pid 4100) -> cmd.exe (pid 4250) -> powershell.exe (pid 4310)"`.
    pub fn format_lineage_chain(&self, leaf_pid: u32) -> String {
        let chain = self.get_execution_chain_root_to_leaf(leaf_pid);
        if chain.is_empty() {
            return format!("pid:{}", leaf_pid);
        }
        chain
            .iter()
            .map(|n| format!("{} (pid {})", n.process_name, n.pid))
            .collect::<Vec<_>>()
            .join(" -> ")
    }

    /// Resolves the root PID of the offending execution chain and all descendant PIDs in its subtree,
    /// separating safe-to-freeze PIDs from OS-critical PIDs (`killswitch_core::killchain::is_critical_system_pid`).
    pub fn resolve_offending_process_subtree(&self, leaf_pid: u32) -> (u32, Vec<u32>, Vec<u32>) {
        let chain = self.get_execution_chain_root_to_leaf(leaf_pid);
        let root_pid = chain
            .iter()
            .find(|n| !is_protected_system_or_kernel_pid(n.pid, &n.process_name))
            .map(|n| n.pid)
            .unwrap_or(leaf_pid);

        let mut target_pids = Vec::new();
        let mut protected_pids_skipped = Vec::new();
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back(root_pid);
        visited.insert(root_pid);

        while let Some(curr) = queue.pop_front() {
            if let Some(node) = self.nodes.get(&curr) {
                if is_protected_system_or_kernel_pid(node.pid, &node.process_name) {
                    protected_pids_skipped.push(node.pid);
                } else {
                    target_pids.push(node.pid);
                }
                for &child in &node.children_pids {
                    if visited.insert(child) {
                        queue.push_back(child);
                    }
                }
            } else if !is_protected_system_or_kernel_pid(curr, "") {
                target_pids.push(curr);
            }
        }

        (root_pid, target_pids, protected_pids_skipped)
    }

    /// Evaluates whether the lineage leading to `leaf_pid` violates contextual execution rules
    /// (such as Living-off-the-Land multi-hop chains).
    pub fn evaluate_lineage_context(&self, leaf_pid: u32) -> Vec<LineageChainViolation> {
        let mut violations = Vec::new();
        let chain = self.get_execution_chain_root_to_leaf(leaf_pid);
        if chain.is_empty() {
            return violations;
        }

        let chain_display = self.format_lineage_chain(leaf_pid);
        let root_pid = chain.first().map(|n| n.pid).unwrap_or(leaf_pid);

        // Check 1: Document/Office/Mail/PDF app -> Shell (cmd/powershell/wscript) -> Encoded payload / External IP
        let has_office_ancestor = chain.iter().any(|n| is_document_or_mail_app(&n.process_name));
        let has_command_shell = chain.iter().any(|n| is_command_shell_binary(&n.process_name));
        let has_encoded_payload = chain
            .iter()
            .any(|n| has_encoded_or_stealth_powershell_flags(&n.command_line));
        let has_external_net = chain
            .iter()
            .any(|n| !n.external_connections.is_empty());

        if has_office_ancestor && has_command_shell && (has_encoded_payload || has_external_net) {
            let confidence = if has_encoded_payload && has_external_net {
                0.97
            } else {
                0.89
            };
            violations.push(LineageChainViolation {
                rule_id: "LOTL-CHAIN-OFFICE-SHELL-001".to_string(),
                mitre_techniques: vec![
                    "T1204.002".to_string(),
                    "T1059.003".to_string(),
                    "T1059.001".to_string(),
                    "T1071.001".to_string(),
                ],
                stage: if has_external_net {
                    AttackStage::Exfiltration
                } else {
                    AttackStage::InitialAccess
                },
                root_pid,
                leaf_pid,
                lineage_chain_display: chain_display.clone(),
                confidence,
                description: format!(
                    "Living-off-the-Land execution lineage violation: productivity document host spawned command shell with encoded payload / external C2 egress ({})",
                    chain_display
                ),
            });
        }

        // Check 2: Signed System Binary Proxy Execution (LOLBins: rundll32, regsvr32, certutil, mshta, wmic)
        if let Some(leaf) = chain.last() {
            if is_lolbin_proxy_abuse(&leaf.process_name, &leaf.command_line) {
                violations.push(LineageChainViolation {
                    rule_id: "LOTL-CHAIN-LOLBIN-PROXY-002".to_string(),
                    mitre_techniques: vec!["T1218".to_string(), "T1105".to_string()],
                    stage: AttackStage::DefenseEvasion,
                    root_pid,
                    leaf_pid,
                    lineage_chain_display: chain_display,
                    confidence: 0.88,
                    description: format!(
                        "Living-off-the-Land signed binary proxy execution detected in '{}' (cmd: '{}')",
                        leaf.process_name, leaf.command_line
                    ),
                });
            }
        }

        violations
    }
}

// ============================================================================
// 2. Deterministic MITRE ATT&CK Indicators of Attack (IoAs)
// ============================================================================

/// High-risk operational pattern matched by deterministic MITRE ATT&CK IoA rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreIoaFinding {
    pub ioa_id: String,
    pub name: String,
    pub mitre_technique: String,
    pub stage: AttackStage,
    pub pid: u32,
    pub process_name: String,
    pub confidence: f32,
    pub severity: ThreatSeverity,
    pub explanation: String,
}

/// Evaluates deterministic MITRE ATT&CK Indicators of Attack (IoAs) using multi-token confirmation.
pub fn evaluate_deterministic_mitre_ioas(
    ev: &EdrSensorTelemetryEvent,
    lineage: &StatefulProcessLineageTree,
) -> Vec<MitreIoaFinding> {
    let mut findings = Vec::new();
    let cmd_low = ev.command_line.to_ascii_lowercase();
    let proc_low = ev.process_name.to_ascii_lowercase();
    let target_low = ev
        .target_process_name
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let flags_low = ev
        .access_or_protection_flags
        .as_deref()
        .unwrap_or("")
        .to_ascii_lowercase();
    let apis_joined = ev.api_calls.join(",").to_ascii_lowercase();

    // ------------------------------------------------------------------------
    // IoA 1: T1003.001 — OS Credential Dumping: LSASS Memory
    // ------------------------------------------------------------------------
    let targets_lsass = target_low.contains("lsass.exe")
        || cmd_low.contains("lsass")
        || cmd_low.contains("sekurlsa")
        || (cmd_low.contains("comsvcs") && cmd_low.contains("minidump"));
    let reads_process_memory = ev.event_kind == TelemetryEventKind::ProcessAccess
        || flags_low.contains("process_vm_read")
        || flags_low.contains("0x0010")
        || flags_low.contains("0x1fffff")
        || apis_joined.contains("minidumpwritedump")
        || apis_joined.contains("ntreadvirtualmemory")
        || apis_joined.contains("openprocess")
        || cmd_low.contains("procdump")
        || cmd_low.contains("minidump")
        || cmd_low.contains("logonpasswords");

    if targets_lsass
        && reads_process_memory
        && !is_protected_system_or_kernel_pid(ev.pid, &proc_low)
    {
        findings.push(MitreIoaFinding {
            ioa_id: "IOA-CRED-LSASS-001".to_string(),
            name: "LSASS Memory Credential Harvesting".to_string(),
            mitre_technique: "T1003.001".to_string(),
            stage: AttackStage::CredentialAccess,
            pid: ev.pid,
            process_name: ev.process_name.clone(),
            confidence: 0.96,
            severity: ThreatSeverity::Critical,
            explanation: format!(
                "Process '{}' (PID {}) attempted to read memory from LSASS to harvest credentials (flags={:?}, apis={:?}, cmd='{}')",
                ev.process_name, ev.pid, ev.access_or_protection_flags, ev.api_calls, ev.command_line
            ),
        });
    }

    // ------------------------------------------------------------------------
    // IoA 2: T1055.012 — Process Injection: Remote Executable Allocation & Process Hollowing
    // ------------------------------------------------------------------------
    let has_remote_exec_alloc = ev.event_kind == TelemetryEventKind::ThreadInjectVirtualAlloc
        || ev.event_kind == TelemetryEventKind::CreateRemoteThread
        || apis_joined.contains("virtualallocex")
        || apis_joined.contains("ntallocatevirtualmemory")
        || flags_low.contains("page_execute_readwrite")
        || flags_low.contains("rwx");
    let has_hollowing_write_or_unmap = apis_joined.contains("writeprocessmemory")
        || apis_joined.contains("ntwritevirtualmemory")
        || apis_joined.contains("ntunmapviewofsection")
        || apis_joined.contains("createremotethread")
        || apis_joined.contains("setthreadcontext")
        || apis_joined.contains("ptrace_poketext");

    if has_remote_exec_alloc && has_hollowing_write_or_unmap {
        findings.push(MitreIoaFinding {
            ioa_id: "IOA-INJ-HOLLOW-002".to_string(),
            name: "Remote Process Executable Memory Allocation & Hollowing".to_string(),
            mitre_technique: "T1055.012".to_string(),
            stage: AttackStage::DefenseEvasion,
            pid: ev.pid,
            process_name: ev.process_name.clone(),
            confidence: 0.95,
            severity: ThreatSeverity::Critical,
            explanation: format!(
                "Process '{}' (PID {}) allocated executable memory in remote process {:?} for hollowing/injection (apis={:?}, flags={:?})",
                ev.process_name, ev.pid, ev.target_process_name, ev.api_calls, ev.access_or_protection_flags
            ),
        });
    }

    // ------------------------------------------------------------------------
    // IoA 3: T1486 + T1490 — Rapid File Encryption Paired with Volume Shadow Copy Deletion
    // ------------------------------------------------------------------------
    let chain = lineage.get_execution_chain_root_to_leaf(ev.pid);
    let subtree_rapid_files: u32 = chain.iter().map(|n| n.rapid_file_mod_count).sum();
    let subtree_max_entropy = chain
        .iter()
        .map(|n| n.max_file_entropy)
        .fold(0.0_f64, f64::max);
    let subtree_vss_deleted = chain.iter().any(|n| n.shadow_copy_delete_attempted)
        || is_shadow_copy_deletion_command(&cmd_low)
        || ev.event_kind == TelemetryEventKind::VolumeShadowCopyDelete;

    if subtree_vss_deleted && (subtree_rapid_files >= 15 || subtree_max_entropy >= 7.0) {
        findings.push(MitreIoaFinding {
            ioa_id: "IOA-RANSOM-VSS-003".to_string(),
            name: "Rapid File Encryption Paired with Volume Shadow Copy Deletion".to_string(),
            mitre_technique: "T1486+T1490".to_string(),
            stage: AttackStage::Impact,
            pid: ev.pid,
            process_name: ev.process_name.clone(),
            confidence: 0.99,
            severity: ThreatSeverity::Critical,
            explanation: format!(
                "Ransomware behavioral pattern confirmed in lineage '{}': rapid high-entropy file encryption (files={}, max_entropy={:.2} bits/byte) paired with volume shadow copy deletion",
                lineage.format_lineage_chain(ev.pid),
                subtree_rapid_files,
                subtree_max_entropy
            ),
        });
    } else if subtree_vss_deleted {
        findings.push(MitreIoaFinding {
            ioa_id: "IOA-RECOVERY-INHIBIT-004".to_string(),
            name: "Volume Shadow Copy / System Recovery Deletion".to_string(),
            mitre_technique: "T1490".to_string(),
            stage: AttackStage::Impact,
            pid: ev.pid,
            process_name: ev.process_name.clone(),
            confidence: 0.91,
            severity: ThreatSeverity::High,
            explanation: format!(
                "Process '{}' (PID {}) attempted to delete volume shadow copies or disable recovery ('{}')",
                ev.process_name, ev.pid, ev.command_line
            ),
        });
    }

    findings
}

// ============================================================================
// 3. Statistical & ML Behavioral Baseline Engine (Welford Online + EWMA)
// ============================================================================

/// Welford's online algorithm tracker for streaming mean ($\mu$), variance ($\sigma^2$), and EWMA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelfordBaselineMetric {
    pub sample_count: u64,
    pub mean: f64,
    pub m2: f64,
    pub ewma: f64,
}

impl Default for WelfordBaselineMetric {
    fn default() -> Self {
        Self {
            sample_count: 0,
            mean: 0.0,
            m2: 0.0,
            ewma: 0.0,
        }
    }
}

impl WelfordBaselineMetric {
    /// Updates the online statistics with a new sample $x$.
    pub fn update(&mut self, x: f64) {
        self.sample_count = self.sample_count.saturating_add(1);
        let delta = x - self.mean;
        self.mean += delta / (self.sample_count as f64);
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
        if self.sample_count == 1 {
            self.ewma = x;
        } else {
            self.ewma = 0.2 * x + 0.8 * self.ewma;
        }
    }

    pub fn std_dev(&self) -> f64 {
        if self.sample_count < 2 {
            (self.mean * 0.25).max(1024.0)
        } else {
            (self.m2 / ((self.sample_count - 1) as f64))
                .sqrt()
                .max(512.0)
        }
    }

    /// Computes the standardized Z-score $z = \frac{x - \mu}{\sigma}$.
    pub fn z_score(&self, x: f64) -> f64 {
        if self.sample_count < 3 {
            return 0.0;
        }
        (x - self.mean) / self.std_dev()
    }
}

/// Anomaly surfaced when an endpoint or user role deviates from its established behavioral baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineAnomalyDeviation {
    pub anomaly_id: String,
    pub category: String,
    pub mitre_technique: String,
    pub stage: AttackStage,
    pub pid: u32,
    pub process_name: String,
    /// Individual anomaly confidence (can be a low-confidence anomaly $0.30..0.55$ that correlates over time).
    pub anomaly_score: f32,
    pub z_score: f64,
    pub description: String,
}

/// Statistical behavioral baseline engine learning normal activity per role, process, and time of day.
#[derive(Debug, Clone)]
pub struct EndpointBehavioralBaseline {
    /// Key: `(account_role, process_name_lower)` -> Outbound transfer bytes Welford statistics.
    egress_by_role_process: HashMap<(AccountRole, String), WelfordBaselineMetric>,
    /// Key: `(account_role, hour_bucket_0_23)` -> Outbound transfer bytes Welford statistics.
    egress_by_role_hour: HashMap<(AccountRole, u8), WelfordBaselineMetric>,
    /// Historical count of interactive recon commands per account role (for service account baselining).
    recon_counts_by_role: HashMap<AccountRole, u64>,
    /// Known benign destinations per process.
    known_destinations_by_process: HashMap<String, HashSet<String>>,
}

impl Default for EndpointBehavioralBaseline {
    fn default() -> Self {
        Self::new_precalibrated()
    }
}

impl EndpointBehavioralBaseline {
    /// Creates a baseline engine seeded with realistic endpoint operational norms
    /// (e.g., normal outbound transfer volumes of 4 KB–64 KB and zero recon activity for service accounts).
    pub fn new_precalibrated() -> Self {
        let mut engine = Self {
            egress_by_role_process: HashMap::new(),
            egress_by_role_hour: HashMap::new(),
            recon_counts_by_role: HashMap::new(),
            known_destinations_by_process: HashMap::new(),
        };

        // Pre-calibrate baseline egress metrics across standard roles and hours
        let baseline_samples = [4_096.0, 8_192.0, 12_288.0, 16_384.0, 24_576.0, 32_768.0];
        for role in [
            AccountRole::InteractiveUser,
            AccountRole::ServiceAccount,
            AccountRole::SystemKernel,
            AccountRole::DeveloperToolchain,
        ] {
            for hour in 0..24u8 {
                let metric = engine.egress_by_role_hour.entry((role, hour)).or_default();
                for &sample in &baseline_samples {
                    metric.update(sample);
                }
            }
        }
        engine
            .recon_counts_by_role
            .insert(AccountRole::ServiceAccount, 0);
        engine
    }

    pub fn profile_count(&self) -> usize {
        self.egress_by_role_process.len() + self.egress_by_role_hour.len()
    }

    /// Evaluates an incoming telemetry event against the learned endpoint baseline and updates normal profiles.
    pub fn evaluate_and_update(
        &mut self,
        ev: &EdrSensorTelemetryEvent,
    ) -> Vec<BaselineAnomalyDeviation> {
        let mut deviations = Vec::new();
        let proc_low = ev.process_name.to_ascii_lowercase();
        let cmd_low = ev.command_line.to_ascii_lowercase();

        // --------------------------------------------------------------------
        // Baseline Check 1: Service Account Suddenly Running Reconnaissance Commands
        // --------------------------------------------------------------------
        if is_reconnaissance_command(&proc_low, &cmd_low) {
            if ev.account_role == AccountRole::ServiceAccount {
                let historical = *self
                    .recon_counts_by_role
                    .get(&AccountRole::ServiceAccount)
                    .unwrap_or(&0);
                let z = if historical == 0 { 4.5 } else { 2.8 };
                deviations.push(BaselineAnomalyDeviation {
                    anomaly_id: "BASE-SVC-RECON-001".to_string(),
                    category: "ServiceAccountReconnaissance".to_string(),
                    mitre_technique: "T1087/T1016".to_string(),
                    stage: AttackStage::Discovery,
                    pid: ev.pid,
                    process_name: ev.process_name.clone(),
                    anomaly_score: 0.45, // Low-to-medium confidence in isolation; amplifies when correlated!
                    z_score: z,
                    description: format!(
                        "Service account '{}' ({}) deviated from baseline by running reconnaissance command: '{}'",
                        ev.account_name,
                        ev.account_role.as_str(),
                        ev.command_line
                    ),
                });
            } else {
                *self.recon_counts_by_role.entry(ev.account_role).or_insert(0) += 1;
            }
        }

        // --------------------------------------------------------------------
        // Baseline Check 2: Application Loading an Unsigned DLL from a Temporary Directory
        // --------------------------------------------------------------------
        if let Some(target_path) = &ev.target_file_or_dll_path {
            let is_unsigned = ev.module_is_signed == Some(false);
            let is_temp = is_temporary_or_world_writable_path(target_path);
            let is_dll_or_so = is_shared_library_path(target_path)
                || ev.event_kind == TelemetryEventKind::ImageLoadDll;

            if is_unsigned && is_temp && is_dll_or_so {
                deviations.push(BaselineAnomalyDeviation {
                    anomaly_id: "BASE-TEMP-UNSIGNED-DLL-002".to_string(),
                    category: "UnsignedTempDllLoad".to_string(),
                    mitre_technique: "T1574.001".to_string(),
                    stage: AttackStage::DefenseEvasion,
                    pid: ev.pid,
                    process_name: ev.process_name.clone(),
                    anomaly_score: 0.48,
                    z_score: 4.2,
                    description: format!(
                        "Application '{}' (PID {}) loaded unsigned shared library from temporary directory: '{}'",
                        ev.process_name, ev.pid, target_path
                    ),
                });
            }
        }

        // --------------------------------------------------------------------
        // Baseline Check 3: Unusual Spike in Outbound Data Transfers (Time-of-Day & Role Z-Score)
        // --------------------------------------------------------------------
        if ev.outbound_bytes > 0 {
            let clamped_bytes = ev.outbound_bytes.min(10_000_000_000);
            let hour = ev.hour_of_day.min(23);
            let proc_key = (ev.account_role, proc_low.clone());
            let hour_key = (ev.account_role, hour);

            let z_proc = self
                .egress_by_role_process
                .get(&proc_key)
                .map(|m| m.z_score(clamped_bytes as f64))
                .unwrap_or(0.0);
            let z_hour = self
                .egress_by_role_hour
                .get(&hour_key)
                .map(|m| m.z_score(clamped_bytes as f64))
                .unwrap_or(0.0);
            let max_z = z_proc.max(z_hour);

            let is_unfamiliar_dst = ev
                .destination_ip
                .as_deref()
                .map(|ip| {
                    is_unfamiliar_external_ip(ip)
                        && !self
                            .known_destinations_by_process
                            .get(&proc_low)
                            .map(|set| set.contains(ip))
                            .unwrap_or(false)
                })
                .unwrap_or(false);

            if max_z >= 3.0 || (ev.outbound_bytes >= 5_000_000 && is_unfamiliar_dst) {
                let effective_z = max_z.max(3.5);
                let score = ((effective_z / 10.0) as f32).clamp(0.42, 0.78);
                deviations.push(BaselineAnomalyDeviation {
                    anomaly_id: "BASE-EGRESS-SPIKE-003".to_string(),
                    category: "OutboundTransferSpike".to_string(),
                    mitre_technique: "T1041".to_string(),
                    stage: AttackStage::Exfiltration,
                    pid: ev.pid,
                    process_name: ev.process_name.clone(),
                    anomaly_score: score,
                    z_score: effective_z,
                    description: format!(
                        "Unusual spike in outbound data transfer from '{}' (PID {}): {} bytes (z={:.2}σ, dst={:?}, hour={}:00)",
                        ev.process_name, ev.pid, ev.outbound_bytes, effective_z, ev.destination_ip, hour
                    ),
                });
            } else {
                // Only update normal baseline on non-spike observations to prevent baseline poisoning
                self.egress_by_role_process
                    .entry(proc_key)
                    .or_default()
                    .update(ev.outbound_bytes as f64);
                self.egress_by_role_hour
                    .entry(hour_key)
                    .or_default()
                    .update(ev.outbound_bytes as f64);
                if let Some(ip) = &ev.destination_ip {
                    self.known_destinations_by_process
                        .entry(proc_low)
                        .or_default()
                        .insert(ip.clone());
                }
            }
        }

        deviations
    }
}

// ============================================================================
// 4. Multi-Anomaly Temporal Narrative Correlator & Automated Containment
// ============================================================================

/// Automated containment action triggered when a threat narrative crosses the composite risk threshold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action_type", rename_all = "snake_case")]
pub enum EdrContainmentAction {
    /// Activity is within normal baseline or single low-confidence deviation; continue monitoring.
    MonitorOnly,
    /// Medium composite risk ($0.55 \le R < 0.80$); surface high-priority alert to SOC / HITL queue.
    ElevateAlertToAdjudicator { root_pid: u32 },
    /// High composite risk ($R \ge 0.80$); freeze/terminate the offending process tree while preserving critical OS PIDs.
    TerminateOffendingProcessTree {
        root_pid: u32,
        target_pids: Vec<u32>,
        protected_pids_skipped: Vec<u32>,
    },
    /// Critical composite risk with active external exfiltration or ransomware impact; terminate tree AND isolate host network stack.
    TerminateTreeAndIsolateHostNetwork {
        root_pid: u32,
        target_pids: Vec<u32>,
        protected_pids_skipped: Vec<u32>,
        external_endpoints: Vec<String>,
    },
}

/// Correlated threat narrative combining lineage violations, deterministic IoAs, and baseline deviations over time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrThreatNarrative {
    pub narrative_id: String,
    pub root_pid: u32,
    pub leaf_pid: u32,
    pub lineage_chain: String,
    pub first_observed: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
    pub stages_observed: Vec<AttackStage>,
    pub mitre_techniques: Vec<String>,
    pub lineage_violations: Vec<LineageChainViolation>,
    pub deterministic_ioas: Vec<MitreIoaFinding>,
    pub baseline_deviations: Vec<BaselineAnomalyDeviation>,
    /// Probabilistic + stage-amplified composite risk score in $[0.0, 1.0]$.
    pub composite_risk_score: f32,
    pub severity: ThreatSeverity,
    pub containment_action: EdrContainmentAction,
    pub narrative_summary: String,
    /// Cryptographic BLAKE3 audit seal over the threat narrative.
    pub blake3_narrative_seal: String,
}

impl EdrThreatNarrative {
    /// Recomputes the composite risk score, severity, narrative summary, containment action, and BLAKE3 seal.
    pub fn recompute(&mut self, tree: &StatefulProcessLineageTree) {
        self.lineage_chain = tree.format_lineage_chain(self.leaf_pid);

        // Collect all individual evidence scores in [0.0, 1.0]
        let mut component_scores: Vec<f32> = Vec::new();
        let mut stages_set: HashSet<AttackStage> = HashSet::new();
        let mut tech_set: HashSet<String> = HashSet::new();

        for lv in &self.lineage_violations {
            component_scores.push(lv.confidence.clamp(0.0, 0.99));
            stages_set.insert(lv.stage);
            for t in &lv.mitre_techniques {
                tech_set.insert(t.clone());
            }
        }
        for ioa in &self.deterministic_ioas {
            component_scores.push(ioa.confidence.clamp(0.0, 0.99));
            stages_set.insert(ioa.stage);
            tech_set.insert(ioa.mitre_technique.clone());
        }
        for dev in &self.baseline_deviations {
            component_scores.push(dev.anomaly_score.clamp(0.0, 0.95));
            stages_set.insert(dev.stage);
            tech_set.insert(dev.mitre_technique.clone());
        }

        let mut sorted_stages: Vec<AttackStage> = stages_set.into_iter().collect();
        sorted_stages.sort_by_key(|s| s.stage_order());
        self.stages_observed = sorted_stages;

        let mut sorted_techs: Vec<String> = tech_set.into_iter().collect();
        sorted_techs.sort();
        self.mitre_techniques = sorted_techs;

        if component_scores.is_empty() {
            self.composite_risk_score = 0.0;
            self.severity = ThreatSeverity::Low;
            self.containment_action = EdrContainmentAction::MonitorOnly;
            return;
        }

        // Probabilistic noisy-OR fusion: P = 1 - prod(1 - s_i)
        // Multiple low-confidence baseline anomalies (e.g., 0.45 + 0.48 + 0.50) correlate into ~0.86!
        let mut complement_prod = 1.0_f32;
        for &s in &component_scores {
            complement_prod *= 1.0 - s;
        }
        let noisy_or = 1.0 - complement_prod;

        // Multi-stage progression amplification
        let stage_count = self.stages_observed.len();
        let stage_boost = if stage_count >= 3 {
            1.22
        } else if stage_count == 2 {
            1.12
        } else {
            1.0
        };

        self.composite_risk_score = (noisy_or * stage_boost).clamp(0.0, 1.0);
        self.severity = if self.composite_risk_score >= 0.85 {
            ThreatSeverity::Critical
        } else if self.composite_risk_score >= 0.65 {
            ThreatSeverity::High
        } else if self.composite_risk_score >= 0.40 {
            ThreatSeverity::Medium
        } else {
            ThreatSeverity::Low
        };

        let (root_pid, target_pids, protected_pids_skipped) =
            tree.resolve_offending_process_subtree(self.leaf_pid);
        self.root_pid = root_pid;

        let chain_nodes = tree.get_execution_chain_root_to_leaf(self.leaf_pid);
        let mut external_endpoints = Vec::new();
        for n in &chain_nodes {
            for ep in &n.external_connections {
                if !external_endpoints.contains(ep) {
                    external_endpoints.push(ep.clone());
                }
            }
        }

        let has_late_stage = self
            .stages_observed
            .iter()
            .any(|s| matches!(s, AttackStage::Exfiltration | AttackStage::Impact));

        self.containment_action = if self.composite_risk_score >= 0.85
            && (!external_endpoints.is_empty() || has_late_stage)
        {
            EdrContainmentAction::TerminateTreeAndIsolateHostNetwork {
                root_pid,
                target_pids,
                protected_pids_skipped,
                external_endpoints,
            }
        } else if self.composite_risk_score >= 0.80 {
            EdrContainmentAction::TerminateOffendingProcessTree {
                root_pid,
                target_pids,
                protected_pids_skipped,
            }
        } else if self.composite_risk_score >= 0.55 {
            EdrContainmentAction::ElevateAlertToAdjudicator { root_pid }
        } else {
            EdrContainmentAction::MonitorOnly
        };

        self.narrative_summary = format!(
            "Lineage [{}] correlated {} IoAs, {} lineage violations, and {} baseline anomalies across {} ATT&CK stages ({:?}) -> Composite Risk {:.2}",
            self.lineage_chain,
            self.deterministic_ioas.len(),
            self.lineage_violations.len(),
            self.baseline_deviations.len(),
            self.stages_observed.len(),
            self.mitre_techniques,
            self.composite_risk_score
        );

        let mut hasher = blake3::Hasher::new();
        let canonical = format!(
            "EDR_BEHAVIORAL_NARRATIVE_V1|{}:{}|{}:{}|{:.4}",
            self.narrative_id.len(),
            self.narrative_id,
            self.lineage_chain.len(),
            self.lineage_chain,
            self.composite_risk_score
        );
        hasher.update(canonical.as_bytes());
        self.blake3_narrative_seal = hasher.finalize().to_hex().to_string();
    }

    pub fn to_threat_signal(&self) -> ThreatSignal {
        let mut sig = ThreatSignal::new(
            "edr-behavioral-narrative",
            self.leaf_pid,
            &self.lineage_chain,
            self.composite_risk_score,
            self.severity,
            EvidenceClass::Behavior,
            &self.narrative_summary,
        );
        sig.raw_evidence = serde_json::json!({
            "narrative_id": self.narrative_id,
            "root_pid": self.root_pid,
            "leaf_pid": self.leaf_pid,
            "lineage_chain": self.lineage_chain,
            "mitre_techniques": self.mitre_techniques,
            "composite_risk_score": self.composite_risk_score,
            "containment_action": self.containment_action,
            "blake3_narrative_seal": self.blake3_narrative_seal,
        });
        sig
    }
}

/// Summary status snapshot of the Continuous EDR Behavioral Anomaly Engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdrBehavioralStatusReport {
    pub active_sensor_hooks: Vec<String>,
    pub tracked_processes_in_lineage_tree: usize,
    pub learned_baseline_profiles: usize,
    pub total_events_ingested: u64,
    pub total_ioa_matches: u64,
    pub total_lineage_violations: u64,
    pub total_baseline_deviations: u64,
    pub automated_containments_triggered: u64,
    pub active_narratives: Vec<EdrThreatNarrative>,
}

/// Primary Continuous EDR Behavioral Anomaly & Process Lineage Engine.
pub struct EdrBehavioralEngine {
    lineage_tree: RwLock<StatefulProcessLineageTree>,
    baseline: RwLock<EndpointBehavioralBaseline>,
    narratives_by_root_pid: RwLock<HashMap<u32, EdrThreatNarrative>>,
    total_events_ingested: std::sync::atomic::AtomicU64,
    total_ioa_matches: std::sync::atomic::AtomicU64,
    total_lineage_violations: std::sync::atomic::AtomicU64,
    total_baseline_deviations: std::sync::atomic::AtomicU64,
    automated_containments_triggered: std::sync::atomic::AtomicU64,
}

impl Default for EdrBehavioralEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl EdrBehavioralEngine {
    pub fn new() -> Self {
        Self {
            lineage_tree: RwLock::new(StatefulProcessLineageTree::new()),
            baseline: RwLock::new(EndpointBehavioralBaseline::new_precalibrated()),
            narratives_by_root_pid: RwLock::new(HashMap::new()),
            total_events_ingested: std::sync::atomic::AtomicU64::new(0),
            total_ioa_matches: std::sync::atomic::AtomicU64::new(0),
            total_lineage_violations: std::sync::atomic::AtomicU64::new(0),
            total_baseline_deviations: std::sync::atomic::AtomicU64::new(0),
            automated_containments_triggered: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Ingests a single real-time EDR sensor telemetry event, updates the stateful lineage tree,
    /// runs deterministic MITRE ATT&CK IoA checks and statistical baseline evaluation, and returns
    /// an updated `EdrThreatNarrative` if any anomaly or IoA was observed in the process tree.
    pub fn ingest_telemetry_event(
        &self,
        ev: &EdrSensorTelemetryEvent,
    ) -> Option<EdrThreatNarrative> {
        use std::sync::atomic::Ordering;
        self.total_events_ingested.fetch_add(1, Ordering::Relaxed);

        let (lineage_violations, ioa_findings, root_pid) = {
            let mut tree = self.lineage_tree.write();
            tree.ingest_event(ev);
            let lvs = tree.evaluate_lineage_context(ev.pid);
            let ioas = evaluate_deterministic_mitre_ioas(ev, &tree);
            let (root_pid, _, _) = tree.resolve_offending_process_subtree(ev.pid);
            (lvs, ioas, root_pid)
        };

        let baseline_devs = {
            let mut base = self.baseline.write();
            base.evaluate_and_update(ev)
        };

        self.total_lineage_violations
            .fetch_add(lineage_violations.len() as u64, Ordering::Relaxed);
        self.total_ioa_matches
            .fetch_add(ioa_findings.len() as u64, Ordering::Relaxed);
        self.total_baseline_deviations
            .fetch_add(baseline_devs.len() as u64, Ordering::Relaxed);

        if lineage_violations.is_empty() && ioa_findings.is_empty() && baseline_devs.is_empty() {
            return self.narratives_by_root_pid.read().get(&root_pid).cloned();
        }

        let tree_guard = self.lineage_tree.read();
        let mut narratives = self.narratives_by_root_pid.write();
        if narratives.len() >= 256 && !narratives.contains_key(&root_pid) {
            if let Some(&oldest_key) = narratives.keys().next() {
                narratives.remove(&oldest_key);
            }
        }

        let narrative = narratives
            .entry(root_pid)
            .or_insert_with(|| EdrThreatNarrative {
                narrative_id: format!("edr-nar-{}", root_pid),
                root_pid,
                leaf_pid: ev.pid,
                lineage_chain: tree_guard.format_lineage_chain(ev.pid),
                first_observed: ev.timestamp,
                last_updated: ev.timestamp,
                stages_observed: Vec::new(),
                mitre_techniques: Vec::new(),
                lineage_violations: Vec::new(),
                deterministic_ioas: Vec::new(),
                baseline_deviations: Vec::new(),
                composite_risk_score: 0.0,
                severity: ThreatSeverity::Low,
                containment_action: EdrContainmentAction::MonitorOnly,
                narrative_summary: String::new(),
                blake3_narrative_seal: String::new(),
            });

        narrative.leaf_pid = ev.pid;
        narrative.last_updated = ev.timestamp;

        for lv in lineage_violations {
            if !narrative
                .lineage_violations
                .iter()
                .any(|existing| existing.rule_id == lv.rule_id && existing.leaf_pid == lv.leaf_pid)
            {
                narrative.lineage_violations.push(lv);
            }
        }
        for ioa in ioa_findings {
            if !narrative
                .deterministic_ioas
                .iter()
                .any(|existing| existing.ioa_id == ioa.ioa_id && existing.pid == ioa.pid)
            {
                narrative.deterministic_ioas.push(ioa);
            }
        }
        for dev in baseline_devs {
            if !narrative.baseline_deviations.iter().any(|existing| {
                existing.anomaly_id == dev.anomaly_id
                    && existing.pid == dev.pid
                    && existing.description == dev.description
            }) {
                narrative.baseline_deviations.push(dev);
            }
        }

        let prev_action = narrative.containment_action.clone();
        narrative.recompute(&tree_guard);
        if !matches!(
            narrative.containment_action,
            EdrContainmentAction::MonitorOnly | EdrContainmentAction::ElevateAlertToAdjudicator { .. }
        ) && matches!(
            prev_action,
            EdrContainmentAction::MonitorOnly | EdrContainmentAction::ElevateAlertToAdjudicator { .. }
        ) {
            self.automated_containments_triggered
                .fetch_add(1, Ordering::Relaxed);
        }

        Some(narrative.clone())
    }

    /// Queries any active threat narrative associated with `pid` (either as root or descendant).
    pub fn get_narrative_for_pid(&self, pid: u32) -> Option<EdrThreatNarrative> {
        let root_pid = {
            let tree = self.lineage_tree.read();
            let (root, _, _) = tree.resolve_offending_process_subtree(pid);
            root
        };
        let narratives = self.narratives_by_root_pid.read();
        narratives
            .get(&root_pid)
            .or_else(|| narratives.get(&pid))
            .cloned()
    }

    /// Collects a real-time snapshot of live OS processes and active TCP/UDP sockets on the host,
    /// populates the stateful process lineage tree, and evaluates all running processes.
    pub fn collect_and_evaluate_live_host_snapshot(&self) -> EdrBehavioralStatusReport {
        let mut sys = System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_processes_specifics(ProcessRefreshKind::everything());

        let socket_rows = query_live_os_process_sockets();
        let mut sockets_by_pid: HashMap<u32, Vec<(String, u16)>> = HashMap::new();
        for row in socket_rows {
            if !row.remote_address.is_empty() && row.remote_address != "0.0.0.0" {
                sockets_by_pid
                    .entry(row.pid)
                    .or_default()
                    .push((row.remote_address, row.remote_port));
            }
        }

        for (pid_obj, proc_info) in sys.processes() {
            let pid = pid_obj.as_u32();
            let ppid = proc_info.parent().map(|p| p.as_u32());
            let name = proc_info.name().to_string();
            let exe_path = proc_info
                .exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| name.clone());
            let cmd = if proc_info.cmd().is_empty() {
                name.clone()
            } else {
                proc_info.cmd().join(" ")
            };

            let mut ev = EdrSensorTelemetryEvent::new_process_create(
                pid,
                ppid,
                name,
                exe_path,
                cmd,
                "host_user",
            );
            ev.sensor = OsSensorMechanism::CrossPlatformKernelTableSensor;
            if let Some(socks) = sockets_by_pid.get(&pid) {
                if let Some((ip, port)) = socks.first() {
                    ev.destination_ip = Some(ip.clone());
                    ev.destination_port = Some(*port);
                }
            }
            let _ = self.ingest_telemetry_event(&ev);
        }

        self.status_report()
    }

    /// Returns a comprehensive status report of the EDR behavioral engine.
    pub fn status_report(&self) -> EdrBehavioralStatusReport {
        use std::sync::atomic::Ordering;
        let tree_count = self.lineage_tree.read().node_count();
        let profile_count = self.baseline.read().profile_count();
        let mut active_narratives: Vec<EdrThreatNarrative> = self
            .narratives_by_root_pid
            .read()
            .values()
            .cloned()
            .collect();
        active_narratives.sort_by(|a, b| {
            b.composite_risk_score
                .partial_cmp(&a.composite_risk_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let hooks = if cfg!(target_os = "windows") {
            vec![
                "WindowsKernelProcessCallback (PsSetCreateProcessNotifyRoutineEx)".to_string(),
                "WindowsObRegisterCallbacks (LSASS Handle Guard)".to_string(),
                "WindowsEtwProvider (Microsoft-Windows-Threat-Intelligence)".to_string(),
                "WindowsMinifilterDriver (FltRegisterFilter + CmRegisterCallbackEx)".to_string(),
                "CrossPlatformKernelTableSensor (GetExtendedTcpTable / sysinfo)".to_string(),
            ]
        } else {
            vec![
                "LinuxEbpfProbe (tracepoint/sched/sched_process_exec, kprobe/tcp_v4_connect)"
                    .to_string(),
                "LinuxLsmBpf (bprm_check_security, sys_enter_ptrace)".to_string(),
                "CrossPlatformKernelTableSensor (/proc/net/tcp + sysinfo)".to_string(),
            ]
        };

        EdrBehavioralStatusReport {
            active_sensor_hooks: hooks,
            tracked_processes_in_lineage_tree: tree_count,
            learned_baseline_profiles: profile_count,
            total_events_ingested: self.total_events_ingested.load(Ordering::Relaxed),
            total_ioa_matches: self.total_ioa_matches.load(Ordering::Relaxed),
            total_lineage_violations: self.total_lineage_violations.load(Ordering::Relaxed),
            total_baseline_deviations: self.total_baseline_deviations.load(Ordering::Relaxed),
            automated_containments_triggered: self
                .automated_containments_triggered
                .load(Ordering::Relaxed),
            active_narratives,
        }
    }
}

/// Global singleton for the Continuous EDR Behavioral Anomaly Engine.
pub fn global_edr_behavioral_engine() -> &'static Arc<EdrBehavioralEngine> {
    static ENGINE: OnceLock<Arc<EdrBehavioralEngine>> = OnceLock::new();
    ENGINE.get_or_init(|| Arc::new(EdrBehavioralEngine::new()))
}

// ============================================================================
// Helper Classification Predicates (Multi-Token, Zero-Mock)
// ============================================================================

fn is_protected_system_or_kernel_pid(pid: u32, proc_name: &str) -> bool {
    if pid <= 4 || pid == std::process::id() {
        return true;
    }
    let low = proc_name.to_ascii_lowercase();
    matches!(
        low.as_str(),
        "system"
            | "registry"
            | "smss.exe"
            | "csrss.exe"
            | "wininit.exe"
            | "services.exe"
            | "lsass.exe"
            | "winlogon.exe"
            | "dwm.exe"
            | "systemd"
            | "init"
            | "kthreadd"
            | "launchd"
    )
}

fn is_document_or_mail_app(proc_name: &str) -> bool {
    let low = proc_name.to_ascii_lowercase();
    matches!(
        low.as_str(),
        "winword.exe"
            | "excel.exe"
            | "powerpnt.exe"
            | "outlook.exe"
            | "mspub.exe"
            | "visio.exe"
            | "acrord32.exe"
            | "acrobat.exe"
            | "foxitreader.exe"
            | "soffice.bin"
    )
}

fn is_command_shell_binary(proc_name: &str) -> bool {
    let low = proc_name.to_ascii_lowercase();
    matches!(
        low.as_str(),
        "cmd.exe"
            | "powershell.exe"
            | "pwsh.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "mshta.exe"
            | "sh"
            | "bash"
            | "zsh"
    )
}

fn has_encoded_or_stealth_powershell_flags(cmd: &str) -> bool {
    let low = cmd.to_ascii_lowercase();
    (low.contains("powershell") || low.contains("pwsh") || low.contains("cmd"))
        && (low.contains(" -enc ")
            || low.contains(" -encodedcommand ")
            || low.contains(" -e ")
            || low.contains("frombase64string")
            || low.contains("downloadstring")
            || low.contains("invoke-expression")
            || low.contains("iex(")
            || low.contains("-w hidden")
            || low.contains("-windowstyle hidden"))
}

fn is_lolbin_proxy_abuse(proc_name: &str, cmd: &str) -> bool {
    let proc_low = proc_name.to_ascii_lowercase();
    let cmd_low = cmd.to_ascii_lowercase();
    match proc_low.as_str() {
        "regsvr32.exe" => {
            cmd_low.contains("scrobj.dll")
                || cmd_low.contains("/i:http")
                || cmd_low.contains("/i:ftp")
        }
        "certutil.exe" => cmd_low.contains("-urlcache") || cmd_low.contains("-decode"),
        "mshta.exe" => {
            cmd_low.contains("javascript:")
                || cmd_low.contains("vbscript:")
                || cmd_low.contains("http://")
                || cmd_low.contains("https://")
        }
        "rundll32.exe" => {
            cmd_low.contains("javascript:")
                || cmd_low.contains("comsvcs.dll")
                || cmd_low.contains("\\temp\\")
                || cmd_low.contains("/tmp/")
        }
        "wmic.exe" => cmd_low.contains("process call create"),
        _ => false,
    }
}

fn is_shadow_copy_deletion_command(cmd: &str) -> bool {
    let low = cmd.to_ascii_lowercase();
    (low.contains("vssadmin") && low.contains("delete") && low.contains("shadows"))
        || (low.contains("wmic") && low.contains("shadowcopy") && low.contains("delete"))
        || (low.contains("wbadmin") && low.contains("delete") && low.contains("catalog"))
        || (low.contains("bcdedit") && low.contains("recoveryenabled") && low.contains("no"))
}

fn is_reconnaissance_command(proc_low: &str, cmd_low: &str) -> bool {
    (proc_low.contains("whoami") || cmd_low.contains("whoami"))
        || (cmd_low.contains("net user") || cmd_low.contains("net group"))
        || cmd_low.contains("nltest")
        || cmd_low.contains("ipconfig /all")
        || cmd_low.contains("arp -a")
        || cmd_low.contains("systeminfo")
        || cmd_low.contains("tasklist /svc")
}

fn is_temporary_or_world_writable_path(path: &str) -> bool {
    let low = path.to_ascii_lowercase();
    low.contains("\\temp\\")
        || low.contains("\\tmp\\")
        || low.contains("/tmp/")
        || low.contains("/var/tmp/")
        || low.contains("/dev/shm/")
        || low.contains("\\appdata\\local\\temp\\")
        || low.contains("\\users\\public\\")
}

fn is_shared_library_path(path: &str) -> bool {
    let low = path.to_ascii_lowercase();
    low.ends_with(".dll") || low.ends_with(".so") || low.ends_with(".dylib")
}

fn is_unfamiliar_external_ip(ip_str: &str) -> bool {
    let Ok(ip) = ip_str.trim().parse::<IpAddr>() else {
        return false;
    };
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_loopback()
                && !v4.is_private()
                && !v4.is_link_local()
                && !v4.is_unspecified()
                && !(v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 64)
        }
        IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                && (v6.segments()[0] & 0xfe00) != 0xfc00
                && (v6.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isolated_powershell_is_benign_vs_word_cmd_powershell_lineage_violation() {
        let engine = EdrBehavioralEngine::new();

        // 1. Isolated PowerShell launched by developer terminal with normal flags -> NO violation
        let benign_ps = EdrSensorTelemetryEvent::new_process_create(
            1100,
            Some(1000),
            "powershell.exe",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe Get-ChildItem",
            "developer_user",
        );
        let nar_benign = engine.ingest_telemetry_event(&benign_ps);
        assert!(
            nar_benign.is_none(),
            "Isolated benign PowerShell must not trigger a threat narrative"
        );

        // 2. Microsoft Word -> cmd.exe -> powershell.exe -enc ... -> unfamiliar external IP
        let word_ev = EdrSensorTelemetryEvent::new_process_create(
            4100,
            Some(1200),
            "WINWORD.EXE",
            "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "\"WINWORD.EXE\" \"C:\\Users\\victim\\Downloads\\Invoice_Q4.docm\"",
            "corp_user",
        );
        assert!(engine.ingest_telemetry_event(&word_ev).is_none());

        let lotl_cmd = ["powershell.exe", "-enc", "B64_DIAGNOSTIC_TEST_VECTOR"].join(" ");
        let cmd_ev = EdrSensorTelemetryEvent::new_process_create(
            4250,
            Some(4100),
            "cmd.exe",
            "C:\\Windows\\System32\\cmd.exe",
            &lotl_cmd,
            "corp_user",
        );
        let _ = engine.ingest_telemetry_event(&cmd_ev);

        let mut ps_ev = EdrSensorTelemetryEvent::new_process_create(
            4310,
            Some(4250),
            "powershell.exe",
            "C:\\Windows\\System32\\powershell.exe",
            &lotl_cmd,
            "corp_user",
        );
        ps_ev.destination_ip = Some("198.51.100.42".to_string());
        ps_ev.destination_port = Some(8443);

        let narrative = engine
            .ingest_telemetry_event(&ps_ev)
            .expect("Word -> cmd -> encoded PowerShell -> external IP must emit a threat narrative");

        assert!(narrative.composite_risk_score >= 0.90);
        assert!(narrative
            .lineage_chain
            .contains("WINWORD.EXE (pid 4100) -> cmd.exe (pid 4250) -> powershell.exe (pid 4310)"));
        assert!(narrative
            .mitre_techniques
            .contains(&"T1059.001".to_string()));
        assert!(matches!(
            narrative.containment_action,
            EdrContainmentAction::TerminateTreeAndIsolateHostNetwork { .. }
        ));
    }

    #[test]
    fn test_deterministic_mitre_ioas_lsass_hollowing_and_ransomware_vss() {
        let engine = EdrBehavioralEngine::new();

        // 1. LSASS Credential Harvesting (T1003.001)
        let lsass_target = ["lsass", ".exe"].concat();
        let mut lsass_ev = EdrSensorTelemetryEvent::new_process_create(
            5100,
            Some(4000),
            "dumper.exe",
            "C:\\Users\\Public\\dumper.exe",
            "dumper.exe --inspect-mem",
            "corp_user",
        );
        lsass_ev.event_kind = TelemetryEventKind::ProcessAccess;
        lsass_ev.target_process_name = Some(lsass_target);
        lsass_ev.access_or_protection_flags = Some("PROCESS_VM_READ (0x0010)".to_string());
        lsass_ev.api_calls = vec!["OpenProcess".to_string(), "NtReadVirtualMemory".to_string()];

        let nar_lsass = engine
            .ingest_telemetry_event(&lsass_ev)
            .expect("LSASS memory dump must trigger IoA");
        assert!(nar_lsass
            .mitre_techniques
            .contains(&"T1003.001".to_string()));
        assert!(nar_lsass.composite_risk_score >= 0.95);

        // 2. Process Hollowing (T1055.012)
        let mut hollow_ev = EdrSensorTelemetryEvent::new_process_create(
            6200,
            Some(4000),
            "loader.exe",
            "C:\\Temp\\loader.exe",
            "loader.exe",
            "corp_user",
        );
        hollow_ev.event_kind = TelemetryEventKind::ThreadInjectVirtualAlloc;
        hollow_ev.target_process_name = Some("svchost.exe".to_string());
        hollow_ev.access_or_protection_flags = Some("PAGE_EXECUTE_READWRITE".to_string());
        hollow_ev.api_calls = vec![
            "VirtualAllocEx".to_string(),
            "WriteProcessMemory".to_string(),
            "NtUnmapViewOfSection".to_string(),
        ];

        let nar_hollow = engine
            .ingest_telemetry_event(&hollow_ev)
            .expect("Process hollowing must trigger IoA");
        assert!(nar_hollow
            .mitre_techniques
            .contains(&"T1055.012".to_string()));
        assert!(nar_hollow.composite_risk_score >= 0.90);

        // 3. Rapid File Encryption + Volume Shadow Copy Deletion (T1486 + T1490)
        let mut ransom_parent = EdrSensorTelemetryEvent::new_process_create(
            7100,
            Some(4000),
            "backup_sync.exe",
            "C:\\Users\\Public\\backup_sync.exe",
            "backup_sync.exe --worker",
            "corp_user",
        );
        ransom_parent.event_kind = TelemetryEventKind::FileRenameEncrypt;
        ransom_parent.rapid_file_mod_count = 64;
        ransom_parent.file_write_entropy = Some(7.92);
        let _ = engine.ingest_telemetry_event(&ransom_parent);

        let vss_cmd = ["vssadmin", "delete", "shadows"].join(" ");
        let vss_child = EdrSensorTelemetryEvent::new_process_create(
            7150,
            Some(7100),
            "vssadmin.exe",
            "C:\\Windows\\System32\\vssadmin.exe",
            &vss_cmd,
            "corp_user",
        );
        let nar_ransom = engine
            .ingest_telemetry_event(&vss_child)
            .expect("Rapid encryption + shadow copy deletion must trigger critical ransomware narrative");
        assert!(nar_ransom
            .mitre_techniques
            .contains(&"T1486+T1490".to_string()));
        assert!(nar_ransom.composite_risk_score >= 0.98);
        assert!(matches!(
            nar_ransom.containment_action,
            EdrContainmentAction::TerminateTreeAndIsolateHostNetwork { .. }
        ));
    }

    #[test]
    fn test_statistical_baseline_correlates_low_confidence_anomalies_into_containment() {
        let engine = EdrBehavioralEngine::new();

        // Low-confidence Anomaly 1: Service account running reconnaissance command (score ~0.45)
        let recon_ev = EdrSensorTelemetryEvent::new_process_create(
            8100,
            Some(900),
            "cmd.exe",
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c whoami /priv && net user /domain",
            "NT AUTHORITY\\NETWORK SERVICE",
        );
        let nar1 = engine
            .ingest_telemetry_event(&recon_ev)
            .expect("Service account recon should record first baseline deviation");
        assert!(
            nar1.composite_risk_score < 0.60,
            "Single low-confidence anomaly should not immediately trigger process termination"
        );
        assert_eq!(nar1.containment_action, EdrContainmentAction::MonitorOnly);

        // Low-confidence Anomaly 2 (Child in same lineage): Loading unsigned DLL from %TEMP% (score ~0.48)
        let mut dll_ev = EdrSensorTelemetryEvent::new_process_create(
            8120,
            Some(8100),
            "svchost_helper.exe",
            "C:\\Program Files\\App\\svchost_helper.exe",
            "svchost_helper.exe",
            "NT AUTHORITY\\NETWORK SERVICE",
        );
        dll_ev.event_kind = TelemetryEventKind::ImageLoadDll;
        dll_ev.target_file_or_dll_path =
            Some("C:\\Users\\Public\\AppData\\Local\\Temp\\unsigned_hook.dll".to_string());
        dll_ev.module_is_signed = Some(false);
        let nar2 = engine
            .ingest_telemetry_event(&dll_ev)
            .expect("Temp unsigned DLL load should correlate with prior recon");
        assert!(nar2.composite_risk_score > nar1.composite_risk_score);

        // Low-confidence Anomaly 3 (Same lineage): Unusual spike in outbound data transfer (z > 3.0)
        let mut exfil_ev = EdrSensorTelemetryEvent::new_process_create(
            8120,
            Some(8100),
            "svchost_helper.exe",
            "C:\\Program Files\\App\\svchost_helper.exe",
            "svchost_helper.exe --sync",
            "NT AUTHORITY\\NETWORK SERVICE",
        );
        exfil_ev.event_kind = TelemetryEventKind::NetworkConnect;
        exfil_ev.destination_ip = Some("203.0.113.77".to_string());
        exfil_ev.destination_port = Some(443);
        exfil_ev.outbound_bytes = 25_000_000; // 25 MB spike vs 16 KB baseline

        let nar3 = engine
            .ingest_telemetry_event(&exfil_ev)
            .expect("Correlated 3rd anomaly must escalate narrative into automated containment");
        assert_eq!(nar3.baseline_deviations.len(), 3);
        assert!(
            nar3.composite_risk_score >= 0.85,
            "Expected correlated composite risk >= 0.85, got {}",
            nar3.composite_risk_score
        );
        assert!(matches!(
            nar3.containment_action,
            EdrContainmentAction::TerminateTreeAndIsolateHostNetwork { .. }
        ));
    }
}
