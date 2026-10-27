use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use subtle::ConstantTimeEq;

use crate::errors::KillSwitchError;

pub const DEFAULT_ROLLBACK_WATCHDOG_MAX_SECS: u64 = 1800; // 30-minute dead-man failsafe ceiling
pub const DEFAULT_INTERMEDIATE_HEALTH_PROBE_INTERVAL_SECS: u64 = 60; // 60s probe interval
pub const DEFAULT_REQUIRED_CONSECUTIVE_HEALTHY_PROBES: u32 = 3; // 3 clean probes -> early rollback
pub const DEFAULT_CONTROL_PORT: u16 = 3030; // Local HTTP API & WebUI control port

pub const KILLCHAIN_ISOLATE_TOKEN: &str = "CONFIRM ISOLATE";
pub const KILLCHAIN_RESTORE_TOKEN: &str = "CONFIRM RESTORE";
pub const MAX_FAILED_ATTEMPTS: u32 = 3;
pub const LOCKOUT_DURATION_SECS: u64 = 300; // 5 minutes

fn default_rollback_watchdog_max_secs() -> u64 {
    DEFAULT_ROLLBACK_WATCHDOG_MAX_SECS
}

fn default_health_probe_interval_secs() -> u64 {
    DEFAULT_INTERMEDIATE_HEALTH_PROBE_INTERVAL_SECS
}

fn default_required_healthy_probes() -> u32 {
    DEFAULT_REQUIRED_CONSECUTIVE_HEALTHY_PROBES
}

/// Active containment state enum for high-level status inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentLevel {
    /// Host operates normally; no isolation or process freezing.
    Disarmed,
    /// Graduated isolation: specific rogue arm or child process is quarantined.
    SurgicalAutotomy,
    /// Process-level containment: untrusted user-space processes are frozen or tarpitted.
    ProcessFreeze,
    /// Network-level containment: non-loopback egress/ingress blocked.
    NetworkQuarantine,
    /// Full hermetic containment: network quarantine + process freeze + kernel lockdown.
    HermeticIsolation,
}

/// Quarantined Octopus agent arm epoch state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantinedArmEpoch {
    pub arm_id: usize,
    pub arm_name: String,
    pub role: String,
    pub quarantined_epoch: u64,
    pub current_epoch: u64,
    pub quarantined_at: DateTime<Utc>,
    pub reason: String,
    pub signature_verified: bool,
}

/// Active native network isolation rule record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveNetworkRule {
    pub rule_id: String,
    pub engine: String, // "wfp_dynamic", "bfe_registry", "netlink_sock_diag", "landlock"
    pub direction: String, // "inbound", "outbound", "both"
    pub action: String, // "block", "permit"
    pub target_ips: Vec<IpAddr>,
    pub target_ports: Vec<u16>,
    pub low_level_filter_id: Option<u64>, // WFP filter ID if applicable
}

/// Comprehensive operational status of the Kill Chain containment engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainStatus {
    /// True if any level of host or process isolation is currently active.
    pub isolated: bool,
    /// Effective containment level.
    pub containment_level: ContainmentLevel,
    /// Timestamp when isolation was first engaged.
    pub isolated_at: Option<DateTime<Utc>>,
    /// Operator, subagent, or node identifier that initiated isolation.
    pub isolated_by: Option<String>,
    /// Justification or alert reason for isolation.
    pub reason: Option<String>,
    /// True if network quarantine is active.
    pub network_isolated: bool,
    /// Total count of processes currently suspended non-destructively.
    pub processes_frozen_count: usize,
    /// Total count of processes currently placed in the thread tarpit.
    pub processes_tarpitted_count: usize,
    /// True if Ring-0 / kernel lockdown mode is engaged.
    pub kernel_lockdown_active: bool,
    /// Ports explicitly preserved during quarantine (defaults to [3030, 53, 67, 68, 546, 547]).
    pub allowlisted_ports: Vec<u16>,
    /// Network interfaces subjected to quarantine filtering.
    pub quarantined_interfaces: Vec<String>,
    /// List of process IDs currently suspended via NtSuspendProcess / SIGSTOP.
    pub frozen_pids: Vec<u32>,
    /// List of process IDs currently throttled in the ActiveProcessTarpit.
    pub tarpitted_pids: Vec<u32>,
    /// Active network rules currently enforced at kernel layers.
    pub active_network_rules: Vec<ActiveNetworkRule>,
    /// Quarantined Octopus arm generation epochs (keyed by arm_id).
    pub quarantined_arms: HashMap<usize, QuarantinedArmEpoch>,
    /// Timestamp of the most recent containment or disarm state transition.
    pub last_action_timestamp: Option<DateTime<Utc>>,
    /// Seconds remaining if the control interface is in rate-limit lockout.
    pub lockout_remaining_secs: u64,
    /// Maximum allowable isolation time before failsafe rollback (anti-hostage ceiling).
    #[serde(default = "default_rollback_watchdog_max_secs")]
    pub rollback_watchdog_max_secs: u64,
    /// Cadence for intermediate process tree telemetry health probes.
    #[serde(default = "default_health_probe_interval_secs")]
    pub health_probe_interval_secs: u64,
    /// Number of consecutive healthy probes required to trigger automatic early rollback.
    #[serde(default = "default_required_healthy_probes")]
    pub consecutive_healthy_probes_required: u32,
    /// Count of consecutive clean health probes observed so far.
    #[serde(default)]
    pub consecutive_healthy_probes: u32,
    /// Timestamp of the last intermediate health probe execution.
    #[serde(default)]
    pub last_health_probe_timestamp: Option<DateTime<Utc>>,
    /// Result of the last intermediate health probe (true = healthy).
    #[serde(default)]
    pub last_health_probe_passed: Option<bool>,
    /// Summary narrative of the last intermediate health probe.
    #[serde(default)]
    pub last_health_probe_summary: Option<String>,
    /// Cryptographic BLAKE3 digest of the current state snapshot.
    #[serde(default)]
    pub state_hash_blake3: String,
}

impl Default for KillChainStatus {
    fn default() -> Self {
        Self {
            isolated: false,
            containment_level: ContainmentLevel::Disarmed,
            isolated_at: None,
            isolated_by: None,
            reason: None,
            network_isolated: false,
            processes_frozen_count: 0,
            processes_tarpitted_count: 0,
            kernel_lockdown_active: false,
            allowlisted_ports: vec![DEFAULT_CONTROL_PORT, 53, 67, 68, 546, 547],
            quarantined_interfaces: Vec::new(),
            frozen_pids: Vec::new(),
            tarpitted_pids: Vec::new(),
            active_network_rules: Vec::new(),
            quarantined_arms: HashMap::new(),
            last_action_timestamp: None,
            lockout_remaining_secs: 0,
            rollback_watchdog_max_secs: DEFAULT_ROLLBACK_WATCHDOG_MAX_SECS,
            health_probe_interval_secs: DEFAULT_INTERMEDIATE_HEALTH_PROBE_INTERVAL_SECS,
            consecutive_healthy_probes_required: DEFAULT_REQUIRED_CONSECUTIVE_HEALTHY_PROBES,
            consecutive_healthy_probes: 0,
            last_health_probe_timestamp: None,
            last_health_probe_passed: None,
            last_health_probe_summary: None,
            state_hash_blake3: String::new(),
        }
    }
}

impl KillChainStatus {
    /// Computes and updates `state_hash_blake3` over all critical fields.
    pub fn update_hash(&mut self) {
        let serialized = serde_json::to_vec(self).unwrap_or_default();
        self.state_hash_blake3 = blake3::hash(&serialized).to_hex().to_string();
    }

    /// Verifies if a given PID is currently in the frozen or tarpitted set.
    pub fn is_pid_contained(&self, pid: u32) -> bool {
        self.frozen_pids.contains(&pid) || self.tarpitted_pids.contains(&pid)
    }

    /// Checks if a sandboxed arm is currently in quarantine.
    pub fn is_arm_quarantined(&self, arm_id: usize) -> bool {
        self.quarantined_arms.contains_key(&arm_id)
    }
}

/// Identifies the native network isolation backend employed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkIsolationEngine {
    /// Windows Filtering Platform dynamic session (fwpuclnt.dll).
    WindowsWfpDynamic,
    /// Windows Base Filtering Engine registry rules (winreg).
    WindowsBfeRegistry,
    /// Linux raw Netlink socket / sock_diag / nfnetlink.
    LinuxNetlink,
    /// Linux Landlock LSM syscall confinement.
    LinuxLandlock,
    /// macOS Darwin BSD /dev/pf Packet Filter ioctl session.
    DarwinPf,
    /// Mock/Simulated engine for headless testing.
    Simulated,
}

/// Detailed record of network quarantine engagement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsolationReceipt {
    /// Unique receipt UUID.
    pub receipt_id: String,
    /// Dynamic session identifier (e.g. WFP session handle pointer hex or Netlink fd descriptor).
    pub session_id: String,
    /// Native engine used to enforce quarantine.
    pub engine: NetworkIsolationEngine,
    /// Atomic transaction status during installation.
    pub transaction_committed: bool,
    /// Low-level 64-bit filter IDs assigned by Windows WFP `FwpmFilterAdd0`.
    pub wfp_filter_ids: Vec<u64>,
    /// BFE Registry rule value names created under `FirewallRules`.
    pub registry_rule_names: Vec<String>,
    /// Netlink rule identifiers or socket descriptors managed on Linux.
    pub netlink_rule_ids: Vec<String>,
    /// Ports explicitly preserved from isolation (inbound and outbound).
    pub preserved_ports: Vec<u16>,
    /// IP addresses preserved (loopback IPv4 127.0.0.1 and IPv6 ::1).
    pub preserved_ips: Vec<IpAddr>,
    /// Number of active TCP connections immediately terminated via SetTcpEntry or SOCK_DESTROY.
    pub terminated_tcp_connections_count: usize,
    /// Timestamp when isolation was committed.
    pub engaged_at: DateTime<Utc>,
    /// Operator, node, or agent identity that authorized isolation.
    pub engaged_by: String,
    /// Threat context or trigger reason.
    pub reason: String,
    /// BLAKE3 cryptographic hash over the receipt contents.
    pub receipt_hash_blake3: String,
}

impl IsolationReceipt {
    /// Constructs a new IsolationReceipt and automatically computes its BLAKE3 hash.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: String,
        engine: NetworkIsolationEngine,
        wfp_filter_ids: Vec<u64>,
        registry_rule_names: Vec<String>,
        netlink_rule_ids: Vec<String>,
        preserved_ports: Vec<u16>,
        preserved_ips: Vec<IpAddr>,
        terminated_tcp_connections_count: usize,
        engaged_by: String,
        reason: String,
    ) -> Self {
        let receipt_id = format!("receipt-{}", uuid::Uuid::new_v4());
        let engaged_at = Utc::now();
        let payload = format!(
            "{}:{}:{:?}:{}:{}:{}:{}:{}",
            receipt_id,
            session_id,
            engine,
            terminated_tcp_connections_count,
            engaged_at.to_rfc3339(),
            engaged_by,
            reason,
            wfp_filter_ids.len() + registry_rule_names.len() + netlink_rule_ids.len()
        );
        let receipt_hash_blake3 = blake3::hash(payload.as_bytes()).to_hex().to_string();

        Self {
            receipt_id,
            session_id,
            engine,
            transaction_committed: true,
            wfp_filter_ids,
            registry_rule_names,
            netlink_rule_ids,
            preserved_ports,
            preserved_ips,
            terminated_tcp_connections_count,
            engaged_at,
            engaged_by,
            reason,
            receipt_hash_blake3,
        }
    }
}

/// High-level lifecycle state of a targeted process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessFreezeStatus {
    /// Target is actively frozen in kernel user-space (NtSuspendProcess / SIGSTOP).
    Frozen,
    /// Target is actively being throttled via thread-level asymmetric sleep/suspend duty cycle.
    Tarpitted,
    /// Target process is executing normally.
    Active,
    /// Target process was previously frozen/tarpitted and has been cleanly resumed.
    Resumed,
    /// Process containment attempted but failed (e.g. AccessDenied, process exited).
    Failed,
    /// Process is protected by OS anchor, dev toolchain, or parent ancestry immunity ("Never Wrong").
    Immune,
}

/// Mechanism employed to isolate or throttle the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessIsolationMethod {
    /// Windows Win32 NtSuspendProcess from ntdll.dll.
    NtSuspendProcess,
    /// Linux POSIX libc::kill(pid, SIGSTOP).
    SigStop,
    /// Thread-level Toolhelp32 snapshot duty-cycle suspension (ActiveProcessTarpit).
    ThreadTarpit,
    /// Linux Cgroup v2 freezer (cgroup.freeze = 1).
    CgroupV2,
}

/// Metrics and duty-cycle statistics for processes placed in the thread tarpit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadTarpitMetrics {
    /// Number of individual threads trapped and suspended within the process.
    pub threads_trapped_count: usize,
    /// Suspended duration per cycle in milliseconds (e.g. 50ms).
    pub duty_cycle_suspend_ms: u64,
    /// Active telemetry observation window per cycle in milliseconds (e.g. 8ms).
    pub duty_cycle_observe_ms: u64,
    /// Cumulative duty cycles completed since trapping began.
    pub cycles_completed: u64,
    /// Total cumulative time in milliseconds that threads spent suspended.
    pub cumulative_suspended_ms: u64,
    /// Timestamp of the most recent duty cycle execution.
    pub last_cycle_timestamp: Option<DateTime<Utc>>,
}

/// Comprehensive tracking state for an individual process subject to containment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessIsolationState {
    /// Process ID.
    pub pid: u32,
    /// Process executable name (e.g. "beacon.exe").
    pub process_name: String,
    /// Full normalized filesystem path to the executable.
    pub executable_path: Option<PathBuf>,
    /// BLAKE3 digest of the on-disk binary image.
    pub image_digest_blake3: Option<String>,
    /// Parent Process ID (PPID) if discoverable.
    pub parent_pid: Option<u32>,
    /// Current suspension or tarpit status.
    pub status: ProcessFreezeStatus,
    /// Isolation method applied.
    pub method: ProcessIsolationMethod,
    /// Timestamp when process was suspended.
    pub suspended_at: Option<DateTime<Utc>>,
    /// Timestamp when process was resumed.
    pub resumed_at: Option<DateTime<Utc>>,
    /// Thread-level tarpit metrics (if method == ThreadTarpit).
    pub tarpit_metrics: Option<ThreadTarpitMetrics>,
    /// Error message if status == Failed or reason if status == Immune.
    pub status_detail: Option<String>,
}

impl ProcessIsolationState {
    /// Creates a record for a successfully frozen process.
    pub fn new_frozen(
        pid: u32,
        process_name: String,
        executable_path: Option<PathBuf>,
        method: ProcessIsolationMethod,
    ) -> Self {
        Self {
            pid,
            process_name,
            executable_path,
            image_digest_blake3: None,
            parent_pid: None,
            status: ProcessFreezeStatus::Frozen,
            method,
            suspended_at: Some(Utc::now()),
            resumed_at: None,
            tarpit_metrics: None,
            status_detail: None,
        }
    }

    /// Marks the process as resumed.
    pub fn mark_resumed(&mut self) {
        self.status = ProcessFreezeStatus::Resumed;
        self.resumed_at = Some(Utc::now());
    }
}

/// Detailed anomaly detected during process tree health probing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthProbeAnomaly {
    pub anomaly_id: String,
    pub kind: ProbeAnomalyKind,
    pub offending_pid: Option<u32>,
    pub process_name: Option<String>,
    pub command_line: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeAnomalyKind {
    /// High-risk signature or malware name found in an unfrozen process.
    UnfrozenSuspiciousProcess,
    /// Child process spawned from a frozen/quarantined parent process.
    OrphanedMaliciousChild,
    /// A required OS core service (e.g. PID 4, explorer.exe, svchost.exe) is absent or terminated.
    CriticalOsAnchorMissing,
    /// Unauthorized socket attempt detected during network quarantine.
    UnauthorizedSocketActivity,
    /// Error accessing or walking the OS process tree.
    ProcessTreeAccessFailure,
}

/// Structured report generated by an intermediate process tree health probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillChainHealthProbeReport {
    /// Probe execution timestamp.
    pub timestamp: DateTime<Utc>,
    /// Overall health verdict: true if all checks passed cleanly with zero anomalies.
    pub process_tree_integrity_ok: bool,
    /// Total number of system processes evaluated during the probe scan.
    pub total_processes_scanned: usize,
    /// Number of verified critical OS infrastructure anchors (PID 0, 1, 4, svchost, etc.).
    pub critical_os_anchors_verified: usize,
    /// Number of frozen PIDs verified to still be in suspended state.
    pub frozen_pids_monitored: usize,
    /// Unfrozen processes that matched high-risk malware markers.
    pub suspicious_unfrozen_processes: Vec<String>,
    /// PIDs of children spawned from quarantined parents.
    pub orphaned_malicious_children: Vec<u32>,
    /// Full structured list of anomalies detected during the probe.
    pub detected_anomalies: Vec<HealthProbeAnomaly>,
    /// Consecutive clean probe count attained (including this probe).
    pub consecutive_healthy_probes: u32,
    /// Target clean probe count required for early rollback (default: 3).
    pub required_healthy_probes: u32,
    /// True if consecutive_healthy_probes >= required_healthy_probes.
    pub eligible_for_early_rollback: bool,
    /// Hard dead-man timeout ceiling in seconds (default: 1800).
    pub rollback_watchdog_max_secs: u64,
    /// Interval in seconds between probes (default: 60).
    pub probe_interval_secs: u64,
    /// BLAKE3 cryptographic hash over the report payload.
    pub probe_hash_blake3: String,
    /// Human-readable summary of probe findings.
    pub summary: String,
}

impl KillChainHealthProbeReport {
    /// Computes the deterministic BLAKE3 signature of the probe report.
    pub fn compute_hash(
        timestamp: &DateTime<Utc>,
        ok: bool,
        scanned: usize,
        anchors: usize,
        consecutive: u32,
        summary: &str,
    ) -> String {
        let payload = format!(
            "{}:{}:{}:{}:{}:{}",
            timestamp.to_rfc3339(),
            ok,
            scanned,
            anchors,
            consecutive,
            summary
        );
        blake3::hash(payload.as_bytes()).to_hex().to_string()
    }
}

/// Immutable record appended to the BLAKE3-chained audit ledger (`killchain_state.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillChainHistoryEntry {
    pub timestamp: String,
    pub action: String, // "ENGAGED" or "DISARMED"
    pub operator: String,
    pub reason: String,
    pub prev_event_hash: String,
    pub event_hash: String,
}

/// Cryptographic hash algorithm used for stored admin credential verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminHashAlgorithm {
    /// High-speed BLAKE3 hash digest.
    Blake3,
    /// Standard SHA-256 hash digest.
    Sha256,
    /// Linux /etc/shadow crypt(3) FFI hash ($6$ SHA-512 or $y$ yescrypt).
    LinuxShadowCrypt,
}

/// Stored admin credential hash representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAdminHash {
    pub algorithm: AdminHashAlgorithm,
    pub hash_hex: String,
    pub salt: Option<String>,
}

/// Incoming operator credentials supplied for an emergency containment or restoration action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorCredentials {
    /// Operator identifier (e.g. "admin", "analyst-01").
    pub operator_id: String,
    /// Bearer or master bypass token (e.g. from environment or secret vault).
    pub auth_token: Option<String>,
    /// Password or PIN phrase provided by the human operator.
    pub password: Option<String>,
    /// Process ID of the process requesting the action (used for caller anti-hijacking validation).
    pub caller_pid: Option<u32>,
    /// Required confirmation phrase ("CONFIRM ISOLATE" or "CONFIRM RESTORE").
    pub confirmation_phrase: Option<String>,
}

/// Method by which authentication succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// Authenticated via Master Token (bypasses lockout).
    MasterTokenBypass,
    /// Authenticated via `KILLSWITCH_ADMIN_PASSWORD` / `OSOOSI_ADMIN_PASSWORD` env var.
    EnvironmentPassword,
    /// Authenticated against stored BLAKE3 or SHA-256 admin password hash file.
    StoredHashMatch,
    /// Authenticated via Linux /etc/shadow crypt(3) FFI.
    LinuxShadowCryptFfi,
    /// Authenticated as recognized local operator identity without slow LogonUserW.
    RecognizedLocalOperator,
}

/// Result of an operator authentication attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthResult {
    /// Authentication succeeded.
    Success {
        operator: String,
        method: AuthMethod,
        authenticated_at: DateTime<Utc>,
    },
    /// Invalid credentials supplied; returns remaining strikes before lockout.
    Failed {
        reason: String,
        attempts_remaining: u32,
    },
    /// Interface is locked due to repeated authentication failures (3-strike lockout).
    LockedOut {
        remaining_seconds: u64,
        locked_until: DateTime<Utc>,
    },
    /// Caller PID is invalid or currently frozen under containment (Anti-Hijacking defense).
    CallerQuarantined {
        caller_pid: u32,
        reason: String,
    },
}

impl AuthResult {
    pub fn is_success(&self) -> bool {
        matches!(self, AuthResult::Success { .. })
    }
}

/// Rate-limiting lockout state with 3-strike backoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockoutState {
    /// True if the interface is actively locked out.
    pub is_locked: bool,
    /// Number of consecutive failed attempts recorded.
    pub failed_attempts: u32,
    /// Maximum allowed attempts before lockout (3).
    pub max_failed_attempts: u32,
    /// Total lockout duration in seconds (300).
    pub lockout_duration_secs: u64,
    /// Timestamp when lockout was enforced.
    pub locked_at: Option<DateTime<Utc>>,
    /// Seconds remaining until lockout expires.
    pub lockout_remaining_secs: u64,
    /// PID of the caller that incurred the most recent failure.
    pub last_failed_caller_pid: Option<u32>,
}

impl Default for LockoutState {
    fn default() -> Self {
        Self {
            is_locked: false,
            failed_attempts: 0,
            max_failed_attempts: MAX_FAILED_ATTEMPTS,
            lockout_duration_secs: LOCKOUT_DURATION_SECS,
            locked_at: None,
            lockout_remaining_secs: 0,
            last_failed_caller_pid: None,
        }
    }
}

impl LockoutState {
    /// Checks if lockout is currently active, auto-releasing if duration has elapsed.
    pub fn is_currently_locked(&mut self) -> bool {
        if !self.is_locked {
            return false;
        }

        if let Some(locked_at) = self.locked_at {
            let elapsed = Utc::now().signed_duration_since(locked_at).num_seconds();
            if elapsed >= self.lockout_duration_secs as i64 {
                // Auto-expire lockout
                self.reset();
                false
            } else {
                let remaining = self.lockout_duration_secs.saturating_sub(elapsed as u64);
                self.lockout_remaining_secs = remaining;
                true
            }
        } else {
            self.reset();
            false
        }
    }

    /// Records a failed authentication attempt. Returns `AuthResult::LockedOut` if strikes exhausted,
    /// otherwise `AuthResult::Failed` with attempts remaining.
    pub fn record_failure(&mut self, caller_pid: Option<u32>) -> AuthResult {
        // If already locked out, return LockedOut
        if self.is_currently_locked() {
            let locked_until = self.locked_at.unwrap_or_else(Utc::now)
                + chrono::Duration::seconds(self.lockout_duration_secs as i64);
            return AuthResult::LockedOut {
                remaining_seconds: self.lockout_remaining_secs,
                locked_until,
            };
        }

        self.failed_attempts += 1;
        self.last_failed_caller_pid = caller_pid;

        if self.failed_attempts >= self.max_failed_attempts {
            let now = Utc::now();
            self.is_locked = true;
            self.locked_at = Some(now);
            self.lockout_remaining_secs = self.lockout_duration_secs;
            let locked_until = now + chrono::Duration::seconds(self.lockout_duration_secs as i64);
            AuthResult::LockedOut {
                remaining_seconds: self.lockout_duration_secs,
                locked_until,
            }
        } else {
            let remaining = self.max_failed_attempts.saturating_sub(self.failed_attempts);
            AuthResult::Failed {
                reason: "Invalid credentials".to_string(),
                attempts_remaining: remaining,
            }
        }
    }

    /// Records a successful authentication, resetting failed attempts and lockout.
    pub fn record_success(&mut self) {
        self.reset();
    }

    /// Resets lockout state to normal.
    pub fn reset(&mut self) {
        self.is_locked = false;
        self.failed_attempts = 0;
        self.locked_at = None;
        self.lockout_remaining_secs = 0;
        self.last_failed_caller_pid = None;
    }
}

/// Constant-time string equality check using `subtle::ConstantTimeEq` to prevent timing side channels.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    if a_bytes.len() != b_bytes.len() {
        return false;
    }
    a_bytes.ct_eq(b_bytes).into()
}

/// Validates caller process integrity before executing Kill Chain state changes.
/// Prevents a compromised or quarantined process from invoking or disarming the Kill Chain.
pub fn validate_caller_pid(
    caller_pid: Option<u32>,
    frozen_pids: &[u32],
) -> Result<(), KillSwitchError> {
    if let Some(pid) = caller_pid {
        if pid <= 4 {
            return Err(KillSwitchError::InvalidCallerPid { pid });
        }
        if frozen_pids.contains(&pid) {
            return Err(KillSwitchError::CallerQuarantined { pid });
        }
    }
    Ok(())
}

/// Validates Octopus arm generation epoch token against stored generation epoch.
pub fn validate_arm_generation_epoch(
    arm_id: usize,
    presented_epoch: u64,
    current_epoch: u64,
    is_quarantined: bool,
    quarantine_reason: Option<&str>,
) -> Result<(), KillSwitchError> {
    if is_quarantined {
        return Err(KillSwitchError::ArmQuarantined {
            arm_id,
            role: "quarantined_arm".to_string(),
            epoch: presented_epoch,
            reason: quarantine_reason.unwrap_or("Quarantined").to_string(),
        });
    }
    if presented_epoch < current_epoch {
        return Err(KillSwitchError::StaleGenerationEpoch {
            arm_id,
            expected: current_epoch,
            presented: presented_epoch,
        });
    }
    Ok(())
}

/// Trait implemented by native network isolation controllers (Windows WFP & Linux Netlink).
pub trait NetworkIsolator: Send + Sync {
    /// Engages hermetic network isolation while preserving specified ports.
    fn engage_quarantine(
        &self,
        preserved_ports: &[u16],
        operator: &str,
        reason: &str,
    ) -> Result<IsolationReceipt, KillSwitchError>;

    /// Reverts network isolation and cleans up installed kernel filters.
    fn restore_quarantine(&self, receipt: &IsolationReceipt) -> Result<(), KillSwitchError>;

    /// Terminate active TCP connections.
    fn reset_tcp_connections(&self, target_ips: Option<&[IpAddr]>) -> Result<usize, KillSwitchError>;
}

/// Trait implemented by native process freezing engines (Windows NtSuspendProcess & Linux SIGSTOP).
pub trait ProcessFreezer: Send + Sync {
    /// Non-destructively suspends a process by PID.
    fn freeze_process(&self, pid: u32) -> Result<ProcessIsolationState, KillSwitchError>;

    /// Resumes a previously suspended process by PID.
    fn resume_process(&self, pid: u32) -> Result<ProcessIsolationState, KillSwitchError>;

    /// Enqueues a process into the thread-level tarpit.
    fn tarpit_process(&self, pid: u32) -> Result<ProcessIsolationState, KillSwitchError>;

    /// Releases a process from the thread tarpit.
    fn release_tarpit(&self, pid: u32) -> Result<ProcessIsolationState, KillSwitchError>;

    /// Checks if a PID is immune from containment (critical OS service, dev tool, parent lineage).
    fn is_immune(&self, pid: u32, proc_name: &str) -> bool;
}

/// Trait implemented by operator authentication controllers.
pub trait OperatorAuthenticator: Send + Sync {
    /// Validates supplied credentials against the hybrid auth hierarchy.
    fn authenticate(&self, creds: &OperatorCredentials) -> AuthResult;

    /// Checks if a calling process is authorized (rejects frozen/quarantined callers).
    fn validate_caller(&self, caller_pid: Option<u32>) -> Result<(), KillSwitchError>;

    /// Checks current rate-limiting lockout status.
    fn check_lockout(&self) -> LockoutState;

    /// Manually clears rate-limit lockout.
    fn reset_lockout(&self);
}

/// Trait implemented by process tree health monitoring engines.
pub trait HealthProbeRunner: Send + Sync {
    /// Runs a process tree telemetry integrity probe.
    fn run_probe(&self) -> Result<KillChainHealthProbeReport, KillSwitchError>;

    /// Resets consecutive healthy probe counter upon new containment events.
    fn reset_probe_counter(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lockout_state_3_strikes_and_recovery() {
        let mut state = LockoutState::default();
        assert!(!state.is_currently_locked());

        // Strike 1
        let r1 = state.record_failure(Some(1234));
        assert_eq!(
            r1,
            AuthResult::Failed {
                reason: "Invalid credentials".to_string(),
                attempts_remaining: 2
            }
        );
        assert!(!state.is_currently_locked());

        // Strike 2
        let r2 = state.record_failure(Some(1234));
        assert_eq!(
            r2,
            AuthResult::Failed {
                reason: "Invalid credentials".to_string(),
                attempts_remaining: 1
            }
        );
        assert!(!state.is_currently_locked());

        // Strike 3 - triggers lockout
        let r3 = state.record_failure(Some(1234));
        assert!(matches!(r3, AuthResult::LockedOut { .. }));
        assert!(state.is_currently_locked());

        // Further attempt while locked
        let r4 = state.record_failure(Some(1234));
        assert!(matches!(r4, AuthResult::LockedOut { .. }));

        // Operator success resets
        state.record_success();
        assert!(!state.is_currently_locked());
        assert_eq!(state.failed_attempts, 0);
    }

    #[test]
    fn test_caller_validation() {
        let frozen = vec![500, 600, 700];

        // Valid caller
        assert!(validate_caller_pid(Some(1000), &frozen).is_ok());
        assert!(validate_caller_pid(None, &frozen).is_ok());

        // Kernel/system callers (PID <= 4) rejected
        assert!(matches!(
            validate_caller_pid(Some(0), &frozen),
            Err(KillSwitchError::InvalidCallerPid { pid: 0 })
        ));
        assert!(matches!(
            validate_caller_pid(Some(4), &frozen),
            Err(KillSwitchError::InvalidCallerPid { pid: 4 })
        ));

        // Quarantined caller rejected
        assert!(matches!(
            validate_caller_pid(Some(500), &frozen),
            Err(KillSwitchError::CallerQuarantined { pid: 500 })
        ));
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("CONFIRM ISOLATE", "CONFIRM ISOLATE"));
        assert!(!constant_time_eq("CONFIRM ISOLATE", "CONFIRM RESTORE"));
        assert!(!constant_time_eq("CONFIRM ISOLATE", "CONFIRM ISOLAT"));
    }

    #[test]
    fn test_killchain_status_hash_update() {
        let mut status = KillChainStatus::default();
        assert!(status.state_hash_blake3.is_empty());
        status.update_hash();
        assert!(!status.state_hash_blake3.is_empty());
        let hash1 = status.state_hash_blake3.clone();

        status.isolated = true;
        status.update_hash();
        assert_ne!(hash1, status.state_hash_blake3);
    }
}
