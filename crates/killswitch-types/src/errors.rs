use std::net::IpAddr;
use std::path::PathBuf;
use thiserror::Error;

/// Master error enumeration for the KillSwitch system.
#[derive(Debug, Error)]
pub enum KillSwitchError {
    // -------------------------------------------------------------------------
    // 1. Windows Filtering Platform (WFP) & Windows Network Control Errors
    // -------------------------------------------------------------------------
    #[error("WFP dynamic session initialization failed: Win32 status 0x{0:08X}")]
    WfpEngineOpenFailed(u32),

    #[error("WFP engine handle is null or session has closed")]
    WfpEngineHandleNull,

    #[error("WFP atomic transaction begin failed: Win32 status 0x{0:08X}")]
    WfpTransactionBeginFailed(u32),

    #[error("WFP atomic transaction commit failed: Win32 status 0x{0:08X}")]
    WfpTransactionCommitFailed(u32),

    #[error("WFP transaction abort failed: Win32 status 0x{0:08X}")]
    WfpTransactionAbortFailed(u32),

    #[error("WFP filter addition failed at layer '{layer}': Win32 status 0x{win32_code:08X}")]
    WfpFilterAddFailed { layer: String, win32_code: u32 },

    #[error("WFP filter deletion failed for filter ID {filter_id}: Win32 status 0x{win32_code:08X}")]
    WfpFilterDeleteFailed { filter_id: u64, win32_code: u32 },

    #[error("Required WFP symbol '{symbol}' not found in fwpuclnt.dll")]
    WfpSymbolNotFound { symbol: String },

    #[error("Windows BFE Registry policy error: {0}")]
    BfeRegistryError(String),

    #[error("Direct TCP table query (GetTcpTable) failed: Win32 status 0x{0:08X}")]
    TcpTableQueryFailed(u32),

    #[error("Direct TCP socket reset (SetTcpEntry) failed for {local}:{local_port} -> {remote}:{remote_port}: Win32 status 0x{win32_code:08X}")]
    TcpEntryResetFailed {
        local: IpAddr,
        local_port: u16,
        remote: IpAddr,
        remote_port: u16,
        win32_code: u32,
    },

    // -------------------------------------------------------------------------
    // 2. Linux Netlink & Landlock Kernel Control Errors
    // -------------------------------------------------------------------------
    #[error("Linux Netlink socket creation failed (protocol {protocol}): errno {errno}")]
    NetlinkSocketCreateFailed { protocol: i32, errno: i32 },

    #[error("Linux Netlink socket query / sock_diag failed: {0}")]
    NetlinkSockDiagFailed(String),

    #[error("Linux Netlink SOCK_DESTROY reset failed for 4-tuple {four_tuple}: errno {errno}")]
    NetlinkSockDestroyFailed { four_tuple: String, errno: i32 },

    #[error("Failed to parse Linux /proc/net/tcp or /proc/net/tcp6 at line: '{line}'")]
    ProcNetTcpParseFailed { line: String },

    #[error("Landlock LSM ruleset creation failed: errno {errno}")]
    LandlockRulesetCreateFailed { errno: i32 },

    #[error("Landlock rule addition failed for path '{path}': errno {errno}")]
    LandlockAddRuleFailed { path: PathBuf, errno: i32 },

    #[error("Landlock self-restriction failed (prctl / restrict_self): errno {errno}")]
    LandlockRestrictSelfFailed { errno: i32 },

    #[error("Landlock LSM is not supported on this Linux kernel (requires >= 5.13)")]
    LandlockUnsupported,

    // -------------------------------------------------------------------------
    // 2b. macOS BSD /dev/pf Packet Filter Kernel Errors
    // -------------------------------------------------------------------------
    #[error("macOS PF ioctl failed: command {cmd}: errno {errno}")]
    PfIoctlFailed { cmd: &'static str, errno: i32 },

    #[error("macOS PF device open failed (/dev/pf): errno {errno}")]
    PfDeviceOpenFailed { errno: i32 },

    #[error("macOS Darwin sysctl socket inspection failed: errno {errno}")]
    DarwinSysctlFailed { errno: i32 },

    #[error("macOS Darwin proc_pidinfo failed for PID {pid}: errno {errno}")]
    DarwinProcPidInfoFailed { pid: u32, errno: i32 },

    // -------------------------------------------------------------------------
    // 3. Process Suspension, Freezing & Tarpit Errors
    // -------------------------------------------------------------------------
    #[error("OpenProcess failed for PID {pid}: Win32 status 0x{win32_code:08X}")]
    ProcessOpenFailed { pid: u32, win32_code: u32 },

    #[error("NtSuspendProcess failed for PID {pid}: NTSTATUS 0x{ntstatus:08X}")]
    NtSuspendProcessFailed { pid: u32, ntstatus: i32 },

    #[error("NtResumeProcess failed for PID {pid}: NTSTATUS 0x{ntstatus:08X}")]
    NtResumeProcessFailed { pid: u32, ntstatus: i32 },

    #[error("POSIX kill(SIGSTOP) failed for PID {pid}: errno {errno}")]
    SigStopFailed { pid: u32, errno: i32 },

    #[error("POSIX kill(SIGCONT) failed for PID {pid}: errno {errno}")]
    SigContFailed { pid: u32, errno: i32 },

    #[error("Toolhelp32 thread snapshot failed for PID {pid}: Win32 status 0x{win32_code:08X}")]
    ThreadSnapshotFailed { pid: u32, win32_code: u32 },

    #[error("OpenThread failed for TID {tid} (PID {pid}): Win32 status 0x{win32_code:08X}")]
    OpenThreadFailed { tid: u32, pid: u32, win32_code: u32 },

    #[error("SuspendThread failed for TID {tid}: Win32 status 0x{win32_code:08X}")]
    SuspendThreadFailed { tid: u32, win32_code: u32 },

    #[error("ResumeThread failed for TID {tid}: Win32 status 0x{win32_code:08X}")]
    ResumeThreadFailed { tid: u32, win32_code: u32 },

    #[error("Refusing process containment for protected system binary: PID {pid} ('{name}'): {reason}")]
    ProtectedProcessImmune {
        pid: u32,
        name: String,
        reason: &'static str,
    },

    #[error("Refusing process containment for developer toolchain ancestor: PID {pid} protected by ancestor PID {ancestor_pid} ('{ancestor_name}') at depth {depth}")]
    ParentLineageImmune {
        pid: u32,
        ancestor_pid: u32,
        ancestor_name: String,
        depth: usize,
    },

    // -------------------------------------------------------------------------
    // 4. Operator Authentication, Authorization & Anti-Hijacking Errors
    // -------------------------------------------------------------------------
    #[error("Invalid operator credentials or confirmation phrase rejected")]
    InvalidCredentials,

    #[error("Empty operator credentials provided")]
    EmptyCredentials,

    #[error("Security lockout active: repeated authentication failures. Retry in {remaining_secs}s")]
    AccountLockedOut { remaining_secs: u64 },

    #[error("Anti-Hijacking Violation: Calling process (PID {pid}) is currently frozen under quarantine")]
    CallerQuarantined { pid: u32 },

    #[error("Invalid caller PID {pid}: PIDs <= 4 (Kernel/System/Idle) are not valid callers")]
    InvalidCallerPid { pid: u32 },

    #[error("Linux /etc/shadow parsing or reading failed: {0}")]
    ShadowFileError(String),

    #[error("Linux crypt(3) FFI execution failed: {0}")]
    CryptFfiError(String),

    #[error("Invalid operator credential or token: {0}")]
    AuthenticationFailed(String),

    #[error("Caller validation failed: process {0} is currently frozen or quarantined")]
    QuarantinedCaller(u32),

    #[error("Security rate limit lockout active: {0} seconds remaining")]
    LockoutActive(u64),

    // -------------------------------------------------------------------------
    // 5. Octopus Agent Anomaly & Multi-Ring Containment Errors
    // -------------------------------------------------------------------------
    #[error("Octopus agent arm {arm_id} ({role}) is in quarantine at generation epoch {epoch}")]
    ArmQuarantined {
        arm_id: usize,
        role: String,
        epoch: u64,
        reason: String,
    },

    #[error("Stale generation epoch token for arm {arm_id}: expected epoch >= {expected}, presented {presented}")]
    StaleGenerationEpoch {
        arm_id: usize,
        expected: u64,
        presented: u64,
    },

    #[error("Inter-arm message HMAC-SHA256 signature verification failed for arm {arm_id}")]
    MeshHmacVerificationFailed { arm_id: usize },

    #[error("Lateral privilege sink violation: sender '{sender_role}' is barred from messaging high-privilege sink '{sink_role}'")]
    LateralSinkViolation {
        sender_role: String,
        sink_role: String,
    },

    #[error("Prohibited outbound target (SSRF blocked): target {ip}:{port} violates mathematical IP policy: {reason}")]
    SsrfBlocked {
        ip: IpAddr,
        port: u16,
        reason: &'static str,
    },

    #[error("Unsafe sandbox path traversal detected: path '{path}' rejected: {reason}")]
    PathTraversalBlocked {
        path: String,
        reason: &'static str,
    },

    #[error("Octopus multi-ring violation: {0}")]
    OctopusViolation(String),

    // -------------------------------------------------------------------------
    // 6. State Ledger & Cryptographic Integrity Errors
    // -------------------------------------------------------------------------
    #[error("State ledger IO failure at '{path}': {source}")]
    LedgerIoError {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("State ledger serialization or deserialization failure: {0}")]
    LedgerSerializationError(String),

    #[error("BLAKE3 state hash chain mismatch at entry {index}: expected {expected}, calculated {calculated}")]
    StateHashChainMismatch {
        index: usize,
        expected: String,
        calculated: String,
    },

    #[error("Cryptographic verification failed: {0}")]
    CryptoError(String),

    // -------------------------------------------------------------------------
    // 7. Graph & Generic Fallback Errors
    // -------------------------------------------------------------------------
    #[error("Graph execution halted: {0}")]
    GraphHalted(String),

    #[error("Native OS containment API error: {0}")]
    NativeOsError(String),

    #[error("Service error: {0}")]
    Service(#[from] crate::service::ServiceError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Operation failed: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, KillSwitchError>;
pub type KillSwitchResult<T> = std::result::Result<T, KillSwitchError>;
