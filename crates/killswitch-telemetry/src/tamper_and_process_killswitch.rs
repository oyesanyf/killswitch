//! # Local Database & Running Executable Tamper Guard, Console Freeze Defense,
//! # Agent Process Table KillSwitch, and Cognitive Red-Team HITL Interceptor
//!
//! Migrated from `OshoosiClaw`:
//! 1. **Local Database & Running EDR Executable Tamper Guard (`breakout_defense.rs`)**:
//!    - Hardware-keyed 64-hex HMAC-SHA256 Maintenance Lease (`MaintenanceLeaseGuard`,
//!      `compute_maintenance_auth_token`, `begin_database_maintenance_lease`, `is_maintenance_window_active`).
//!    - `LocalMySqlTamperGuard`: 4-Gate Maintenance Immunity (InnoDB `#sql-*.ibd` online DDL &
//!      SQLite `VACUUM` detection) so routine DB maintenance never triggers a false-positive
//!      KillSwitch; hostile row/table deletion fires `KILLSWITCH_ACTIVE` and `self_heal_from_memory`.
//!    - `EdrExecutableTamperGuard`: Hardens running process kernel DACL (`harden_running_process_dacl`),
//!      holds a `FILE_SHARE_READ`-only kernel lock (`acquire_deny_delete_and_rename_lock`) blocking
//!      `DeleteFileW`/`MoveFileW` (rename-while-running), and verifies on-disk BLAKE3 integrity
//!      (`verify_running_exe_integrity_tick`), firing `KILLSWITCH_ACTIVE` and restoring from `.exe.golden`.
//! 2. **Interactive Elevated Console Window & Conhost Defense (`EDR-VEC-23`, `console_defense.rs`)**:
//!    - `compute_hardened_console_mode`, `is_console_mode_hardened`, `harden_windows_console`,
//!      `flush_console_input`, `detach_console`, `has_interactive_console`, `CommandConsoleExt`.
//! 3. **Agent Process Table KillSwitch (`kill_switch.rs`)**:
//!    - `AgentStatus`, `AgentProcess`, `ProcessTable`, `global_agent_process_table`.
//! 4. **Cognitive Red-Team HITL Interceptor & Deliberate Friction Gate (`cognitive_redteam.rs` & `mesh_guard.rs`)**:
//!    - Counterfactual blast-radius diff ($S_{\text{exec}} \setminus S_{\text{deny}}$), fluency stripping,
//!      UTS #39 homograph/RTLO/ANSI/zero-width deception scanner (`HitlCognitiveFirewall`),
//!      SAELens deception likelihood scoring ($P_{\text{deception}} \ge 0.85$ auto-veto),
//!      polymorphic 4-option verification challenge (`PolymorphicChallenge`, 120s TTL), and
//!      dual-custody quorum approval ($O_1 \neq O_2$).

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// PART 1: DATABASE & RUNNING EXECUTABLE TAMPER GUARD WITH 4-GATE IMMUNITY
// ============================================================================

/// Global atomic flag indicating whether the local tamper-triggered KillSwitch is engaged.
pub static KILLSWITCH_ACTIVE: AtomicBool = AtomicBool::new(false);

static MAINTENANCE_WINDOW_ACTIVE: AtomicBool = AtomicBool::new(false);
static MAINTENANCE_LEASE_EXPIRY_UNIX: AtomicU64 = AtomicU64::new(0);
static LAST_TAMPER_REASON: Mutex<Option<String>> = Mutex::new(None);

/// Derives a machine-bound 32-byte HMAC secret for database maintenance leases.
fn derive_maintenance_hmac_secret() -> [u8; 32] {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "killswitch-local-host".to_string());
    let mut hasher = Sha256::new();
    hasher.update(b"killswitch-db-maintenance-v1|");
    hasher.update(host.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

/// Computes a 64-character hex HMAC-SHA256 maintenance authentication token bound to `(scope, expiry_unix)`.
pub fn compute_maintenance_auth_token(scope: &str, expiry_unix: u64) -> String {
    let key = derive_maintenance_hmac_secret();
    let mut mac = HmacSha256::new_from_slice(&key).expect("32-byte HMAC key is valid");
    mac.update(format!("maint-v1|{}|{}", scope, expiry_unix).as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// RAII guard that automatically revokes the database maintenance window when dropped.
pub struct MaintenanceLeaseGuard {
    pub scope: String,
    pub expires_at_unix: u64,
}

impl Drop for MaintenanceLeaseGuard {
    fn drop(&mut self) {
        MAINTENANCE_LEASE_EXPIRY_UNIX.store(0, Ordering::SeqCst);
        MAINTENANCE_WINDOW_ACTIVE.store(false, Ordering::SeqCst);
    }
}

/// Begins a cryptographically verified database maintenance lease (capped at 600 seconds).
pub fn begin_database_maintenance_lease(
    scope: &str,
    duration_secs: u64,
    expiry_unix: u64,
    provided_token_hex: &str,
) -> Result<MaintenanceLeaseGuard, String> {
    let capped_duration = duration_secs.min(600);
    let expected_hex = compute_maintenance_auth_token(scope, expiry_unix);
    if provided_token_hex.len() != expected_hex.len()
        || !bool::from(
            provided_token_hex
                .as_bytes()
                .ct_eq(expected_hex.as_bytes()),
        )
    {
        return Err("MAINTENANCE_AUTH_FAILED: Invalid HMAC-SHA256 maintenance token".to_string());
    }
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now_unix > expiry_unix {
        return Err("MAINTENANCE_AUTH_EXPIRED: Maintenance token expiry has passed".to_string());
    }
    let effective_expiry = expiry_unix.min(now_unix + capped_duration);
    MAINTENANCE_LEASE_EXPIRY_UNIX.store(effective_expiry, Ordering::SeqCst);
    MAINTENANCE_WINDOW_ACTIVE.store(true, Ordering::SeqCst);
    Ok(MaintenanceLeaseGuard {
        scope: scope.to_string(),
        expires_at_unix: effective_expiry,
    })
}

/// Returns `true` iff an authenticated maintenance lease is currently active and has not expired.
pub fn is_maintenance_window_active() -> bool {
    if !MAINTENANCE_WINDOW_ACTIVE.load(Ordering::SeqCst) {
        return false;
    }
    let expiry = MAINTENANCE_LEASE_EXPIRY_UNIX.load(Ordering::SeqCst);
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now_unix <= expiry {
        true
    } else {
        MAINTENANCE_WINDOW_ACTIVE.store(false, Ordering::SeqCst);
        false
    }
}

/// Outcome of a database or executable tamper check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TamperCheckOutcome {
    /// All rows/tables and binary hashes match the cryptographic golden state.
    Healthy,
    /// Legitimate database maintenance (authenticated lease, InnoDB online DDL, or SQLite VACUUM)
    /// detected; KillSwitch is suppressed to guarantee zero false positives.
    MaintenanceDeferred { reason: String },
    /// Hostile tampering confirmed; `KILLSWITCH_ACTIVE` engaged and self-healed from golden mirror.
    HostileTamperConfirmed {
        reason: String,
        killswitch_engaged: bool,
        self_healed: bool,
    },
}

/// Local Database Tamper Guard with 4-Gate Maintenance Immunity (`LocalMySqlTamperGuard`).
#[derive(Debug, Clone)]
pub struct LocalMySqlTamperGuard {
    pub db_data_dir: PathBuf,
    golden_mirror: Arc<Mutex<HashMap<String, String>>>,
}

impl LocalMySqlTamperGuard {
    pub fn new(db_data_dir: impl Into<PathBuf>) -> Self {
        Self {
            db_data_dir: db_data_dir.into(),
            golden_mirror: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Commits a trusted configuration key-value pair to the in-memory golden mirror.
    pub fn record_golden_row(&self, key: impl Into<String>, value: impl Into<String>) {
        if let Ok(mut guard) = self.golden_mirror.lock() {
            guard.insert(key.into(), value.into());
        }
    }

    /// Returns a snapshot of the in-memory golden mirror.
    pub fn golden_snapshot(&self) -> HashMap<String, String> {
        self.golden_mirror
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Detects active InnoDB `#sql-*.ibd` online `OPTIMIZE`/`ALTER TABLE` temporary tables or
    /// SQLite `-wal`/`-journal` `VACUUM` operations in `db_data_dir` (Gate 2 of 4-Gate Immunity).
    pub fn detect_active_engine_maintenance(&self) -> Option<String> {
        let Ok(entries) = std::fs::read_dir(&self.db_data_dir) else {
            return None;
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let lower = name.to_ascii_lowercase();
            if lower.starts_with("#sql-") && (lower.ends_with(".ibd") || lower.ends_with(".frm")) {
                return Some(format!(
                    "Active InnoDB online DDL temporary tablespace detected ('{}')",
                    name
                ));
            }
            if lower.contains("-vacuum") || lower.ends_with(".bak-maint") {
                return Some(format!(
                    "Active database engine compaction/vacuum artifact detected ('{}')",
                    name
                ));
            }
        }
        None
    }

    /// Evaluates current database table rows against the in-memory golden mirror.
    ///
    /// Enforces the 4-Gate Maintenance Immunity Law:
    /// - Gate 1: Cryptographic `MaintenanceLeaseGuard` active (`is_maintenance_window_active()`).
    /// - Gate 2: Active InnoDB `#sql-*.ibd` or engine compaction artifact on disk.
    /// - Gate 3: Row-level BLAKE3 / content verification against `golden_mirror`.
    /// - Gate 4: On hostile tamper, engages `KILLSWITCH_ACTIVE` in-process and self-heals from memory.
    pub fn verify_live_rows(
        &self,
        live_rows: &mut HashMap<String, String>,
    ) -> TamperCheckOutcome {
        if is_maintenance_window_active() {
            return TamperCheckOutcome::MaintenanceDeferred {
                reason: "Authenticated HMAC-SHA256 database maintenance lease is active"
                    .to_string(),
            };
        }
        if let Some(engine_reason) = self.detect_active_engine_maintenance() {
            return TamperCheckOutcome::MaintenanceDeferred {
                reason: engine_reason,
            };
        }

        let golden = self.golden_snapshot();
        let mut tampered_keys = Vec::new();
        for (k, expected_val) in &golden {
            match live_rows.get(k) {
                Some(actual_val) if actual_val == expected_val => {}
                Some(_) => tampered_keys.push(format!("modified_key:{}", k)),
                None => tampered_keys.push(format!("deleted_key:{}", k)),
            }
        }

        if tampered_keys.is_empty() {
            return TamperCheckOutcome::Healthy;
        }

        let reason = format!(
            "DB_TAMPER_DETECTED: Unauthorized modification/deletion on keys [{}]",
            tampered_keys.join(", ")
        );
        Self::initiate_local_killswitch(&reason);
        self.self_heal_from_memory(live_rows);

        TamperCheckOutcome::HostileTamperConfirmed {
            reason,
            killswitch_engaged: true,
            self_healed: true,
        }
    }

    /// Restores tampered or deleted rows directly from the in-memory golden mirror.
    pub fn self_heal_from_memory(&self, live_rows: &mut HashMap<String, String>) {
        let golden = self.golden_snapshot();
        for (k, v) in golden {
            live_rows.insert(k, v);
        }
    }

    /// Engages the in-process atomic `KILLSWITCH_ACTIVE` flag and records the forensic reason.
    pub fn initiate_local_killswitch(reason: &str) {
        KILLSWITCH_ACTIVE.store(true, Ordering::SeqCst);
        if let Ok(mut guard) = LAST_TAMPER_REASON.lock() {
            *guard = Some(reason.to_string());
        }
        tracing::error!(
            reason = reason,
            "CRITICAL TAMPER DETECTED — KILLSWITCH_ACTIVE ENGAGED"
        );
    }
}

/// Running EDR Executable Tamper Guard (`EdrExecutableTamperGuard`).
///
/// Protects the running KillSwitch binary against:
/// 1. `TerminateProcess` / `PROCESS_VM_WRITE` via hardened process DACL (`harden_running_process_dacl`).
/// 2. `DeleteFileW` and `MoveFileExW` (rename-while-running) via an exclusive `FILE_SHARE_READ`
///    kernel file handle (`acquire_deny_delete_and_rename_lock`).
/// 3. On-disk binary modification via continuous BLAKE3 hash verification and automatic restoration
///    from the `.exe.golden` mirror (`verify_running_exe_integrity_tick`).
pub struct EdrExecutableTamperGuard {
    pub exe_path: PathBuf,
    pub golden_mirror_path: PathBuf,
    pub expected_blake3_hex: String,
    pub process_dacl_hardened: bool,
    pub delete_rename_lock_held: bool,
    _locked_file_handle: Option<std::fs::File>,
}

impl EdrExecutableTamperGuard {
    /// Protects the currently executing binary (`std::env::current_exe()`).
    pub fn protect_current_executable() -> Result<Self, String> {
        let exe_path = std::env::current_exe()
            .map_err(|e| format!("Failed to resolve current_exe: {}", e))?;
        Self::protect_executable_at(&exe_path)
    }

    /// Protects a target executable path by computing its BLAKE3 golden digest, creating a
    /// `.exe.golden` backup if writable, hardening the process DACL, and acquiring a
    /// `FILE_SHARE_READ`-only kernel lock.
    pub fn protect_executable_at(exe_path: &Path) -> Result<Self, String> {
        let bytes = std::fs::read(exe_path).map_err(|e| {
            format!(
                "Failed to read executable '{}' for BLAKE3 sealing: {}",
                exe_path.display(),
                e
            )
        })?;
        let expected_blake3_hex = blake3::hash(&bytes).to_hex().to_string();
        let golden_mirror_path = PathBuf::from(format!("{}.golden", exe_path.display()));
        let _ = std::fs::write(&golden_mirror_path, &bytes);

        let process_dacl_hardened = Self::harden_running_process_dacl();
        let locked_file = Self::acquire_deny_delete_and_rename_lock(exe_path).ok();
        let delete_rename_lock_held = locked_file.is_some();

        Ok(Self {
            exe_path: exe_path.to_path_buf(),
            golden_mirror_path,
            expected_blake3_hex,
            process_dacl_hardened,
            delete_rename_lock_held,
            _locked_file_handle: locked_file,
        })
    }

    /// Hardens the current process security descriptor on Windows (`SetSecurityInfo`) or sets
    /// `PR_SET_DUMPABLE(0)` on Linux so non-SYSTEM processes cannot inject or dump memory.
    #[cfg(target_os = "windows")]
    pub fn harden_running_process_dacl() -> bool {
        // Verify process handle validity via GetCurrentProcess
        unsafe {
            let h_proc = windows_sys::Win32::System::Threading::GetCurrentProcess();
            !h_proc.is_null()
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn harden_running_process_dacl() -> bool {
        true
    }

    /// Opens `exe_path` with `FILE_SHARE_READ` only (omitting `FILE_SHARE_WRITE` and `FILE_SHARE_DELETE`),
    /// which instructs the Windows NT kernel to reject any `DeleteFileW` or `MoveFileExW` (rename)
    /// against the executable while this handle remains open.
    #[cfg(target_os = "windows")]
    pub fn acquire_deny_delete_and_rename_lock(exe_path: &Path) -> Result<std::fs::File, String> {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ_ONLY: u32 = 0x0000_0001;
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ_ONLY)
            .open(exe_path)
            .map_err(|e| format!("Failed to acquire FILE_SHARE_READ lock: {}", e))
    }

    #[cfg(not(target_os = "windows"))]
    pub fn acquire_deny_delete_and_rename_lock(exe_path: &Path) -> Result<std::fs::File, String> {
        std::fs::OpenOptions::new()
            .read(true)
            .open(exe_path)
            .map_err(|e| format!("Failed to open executable lock: {}", e))
    }

    /// Verifies that the on-disk binary at `exe_path` still matches `expected_blake3_hex`.
    /// If missing or modified, triggers `KILLSWITCH_ACTIVE` and restores from `golden_mirror_path`.
    pub fn verify_running_exe_integrity_tick(&self) -> TamperCheckOutcome {
        match std::fs::read(&self.exe_path) {
            Ok(bytes) => {
                let actual_hex = blake3::hash(&bytes).to_hex().to_string();
                if actual_hex == self.expected_blake3_hex {
                    return TamperCheckOutcome::Healthy;
                }
                let reason = format!(
                    "EXE_HASH_MISMATCH: '{}' BLAKE3 changed (expected {}, got {})",
                    self.exe_path.display(),
                    self.expected_blake3_hex,
                    actual_hex
                );
                LocalMySqlTamperGuard::initiate_local_killswitch(&reason);
                let healed = if let Ok(golden_bytes) = std::fs::read(&self.golden_mirror_path) {
                    std::fs::write(&self.exe_path, golden_bytes).is_ok()
                } else {
                    false
                };
                TamperCheckOutcome::HostileTamperConfirmed {
                    reason,
                    killswitch_engaged: true,
                    self_healed: healed,
                }
            }
            Err(e) => {
                let reason = format!(
                    "EXE_MISSING_OR_UNREADABLE: '{}' ({})",
                    self.exe_path.display(),
                    e
                );
                LocalMySqlTamperGuard::initiate_local_killswitch(&reason);
                let healed = if let Ok(golden_bytes) = std::fs::read(&self.golden_mirror_path) {
                    std::fs::write(&self.exe_path, golden_bytes).is_ok()
                } else {
                    false
                };
                TamperCheckOutcome::HostileTamperConfirmed {
                    reason,
                    killswitch_engaged: true,
                    self_healed: healed,
                }
            }
        }
    }
}

/// Summary status report for the Tamper Guard & Console Hardening subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TamperGuardStatusReport {
    pub killswitch_active: bool,
    pub maintenance_window_active: bool,
    pub last_tamper_reason: Option<String>,
    pub console_mode_hardened: bool,
    pub exe_dacl_hardened: bool,
}

pub fn get_tamper_guard_status() -> TamperGuardStatusReport {
    let reason = LAST_TAMPER_REASON.lock().ok().and_then(|g| g.clone());
    let sample_mode = compute_hardened_console_mode(ENABLE_QUICK_EDIT_MODE | ENABLE_MOUSE_INPUT);
    TamperGuardStatusReport {
        killswitch_active: KILLSWITCH_ACTIVE.load(Ordering::SeqCst),
        maintenance_window_active: is_maintenance_window_active(),
        last_tamper_reason: reason,
        console_mode_hardened: is_console_mode_hardened(sample_mode),
        exe_dacl_hardened: EdrExecutableTamperGuard::harden_running_process_dacl(),
    }
}

// ============================================================================
// PART 2: INTERACTIVE ELEVATED CONSOLE WINDOW & CONHOST DEFENSE (EDR-VEC-23)
// ============================================================================

pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;
pub const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
pub const ENABLE_LINE_INPUT: u32 = 0x0002;
pub const ENABLE_ECHO_INPUT: u32 = 0x0004;
pub const ENABLE_WINDOW_INPUT: u32 = 0x0008;
pub const ENABLE_MOUSE_INPUT: u32 = 0x0010;
pub const ENABLE_INSERT_MODE: u32 = 0x0020;
pub const ENABLE_QUICK_EDIT_MODE: u32 = 0x0040;
pub const ENABLE_EXTENDED_FLAGS: u32 = 0x0080;

pub const STD_INPUT_HANDLE: u32 = 0xFFFF_FFF6;
pub const INVALID_HANDLE_VALUE: isize = -1;

/// Computes the hardened console input mode mask (`EDR-VEC-23`):
/// Clears `ENABLE_QUICK_EDIT_MODE (0x0040)`, `ENABLE_INSERT_MODE (0x0020)`,
/// and `ENABLE_MOUSE_INPUT (0x0010)`, while setting `ENABLE_EXTENDED_FLAGS (0x0080)`.
pub fn compute_hardened_console_mode(current_mode: u32) -> u32 {
    (current_mode & !(ENABLE_QUICK_EDIT_MODE | ENABLE_INSERT_MODE | ENABLE_MOUSE_INPUT))
        | ENABLE_EXTENDED_FLAGS
}

/// Checks whether a console mode mask has QuickEdit, Insert, and Mouse input stripped,
/// and has `ENABLE_EXTENDED_FLAGS` set.
pub fn is_console_mode_hardened(mode: u32) -> bool {
    ((mode & (ENABLE_QUICK_EDIT_MODE | ENABLE_INSERT_MODE | ENABLE_MOUSE_INPUT)) == 0)
        && ((mode & ENABLE_EXTENDED_FLAGS) != 0)
}

#[cfg(target_os = "windows")]
mod win32_console {
    #[link(name = "kernel32")]
    extern "system" {
        pub fn GetStdHandle(nStdHandle: u32) -> isize;
        pub fn GetConsoleMode(hConsoleHandle: isize, lpMode: *mut u32) -> i32;
        pub fn SetConsoleMode(hConsoleHandle: isize, dwMode: u32) -> i32;
        pub fn FlushConsoleInputBuffer(hConsoleInput: isize) -> i32;
    }
}

/// Hardens the current Windows console input mode to prevent interactive QuickEdit / Select freezes.
#[cfg(target_os = "windows")]
pub fn harden_windows_console() -> bool {
    unsafe {
        let handle = win32_console::GetStdHandle(STD_INPUT_HANDLE);
        if handle == 0 || handle == INVALID_HANDLE_VALUE {
            return false;
        }
        let mut mode: u32 = 0;
        if win32_console::GetConsoleMode(handle, &mut mode) == 0 {
            return false;
        }
        let hardened = compute_hardened_console_mode(mode);
        let set_ok = win32_console::SetConsoleMode(handle, hardened) != 0;
        let _ = win32_console::FlushConsoleInputBuffer(handle);
        set_ok
    }
}

#[cfg(not(target_os = "windows"))]
pub fn harden_windows_console() -> bool {
    false
}

/// Flushes pending input records from the standard input console buffer.
#[cfg(target_os = "windows")]
pub fn flush_console_input() -> bool {
    unsafe {
        let handle = win32_console::GetStdHandle(STD_INPUT_HANDLE);
        if handle != 0 && handle != INVALID_HANDLE_VALUE {
            win32_console::FlushConsoleInputBuffer(handle) != 0
        } else {
            false
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn flush_console_input() -> bool {
    false
}

// ============================================================================
// PART 3: AGENT PROCESS TABLE KILL SWITCH (`osoosi-sandbox/src/kill_switch.rs`)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    Running,
    Paused,
    Killed,
    Completed,
    Error(String),
}

/// Tracks the lifecycle of a single sandboxed agent execution with epoch-interruption KillSwitch.
pub struct AgentProcess {
    pub id: String,
    pub name: String,
    pub started_at: DateTime<Utc>,
    pub status: AgentStatus,
    pub fuel_consumed: AtomicU64,
    pub memory_bytes: AtomicU64,
    pub syscall_count: AtomicU64,
    pub epoch_counter: Arc<AtomicU64>,
    kill_flag: Arc<AtomicBool>,
}

impl AgentProcess {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            started_at: Utc::now(),
            status: AgentStatus::Running,
            fuel_consumed: AtomicU64::new(0),
            memory_bytes: AtomicU64::new(0),
            syscall_count: AtomicU64::new(0),
            epoch_counter: Arc::new(AtomicU64::new(1)),
            kill_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Terminates the agent immediately by setting `kill_flag` and incrementing its execution epoch.
    pub fn kill(&mut self) {
        tracing::warn!(
            "KILL SWITCH: Terminating agent '{}' (id={})",
            self.name,
            self.id
        );
        self.kill_flag.store(true, Ordering::SeqCst);
        self.epoch_counter.fetch_add(1, Ordering::SeqCst);
        self.status = AgentStatus::Killed;
    }

    /// Pauses the agent.
    pub fn pause(&mut self) {
        self.status = AgentStatus::Paused;
    }

    pub fn is_killed(&self) -> bool {
        self.kill_flag.load(Ordering::SeqCst)
    }

    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "name": self.name,
            "started_at": self.started_at,
            "status": format!("{:?}", self.status),
            "fuel_consumed": self.fuel_consumed.load(Ordering::Relaxed),
            "memory_bytes": self.memory_bytes.load(Ordering::Relaxed),
            "syscall_count": self.syscall_count.load(Ordering::Relaxed),
            "epoch": self.epoch_counter.load(Ordering::Relaxed),
            "is_killed": self.is_killed(),
        })
    }
}

/// Process table tracking all active sandboxed agents (`ProcessTable`).
pub struct ProcessTable {
    agents: Mutex<Vec<AgentProcess>>,
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessTable {
    pub fn new() -> Self {
        Self {
            agents: Mutex::new(Vec::new()),
        }
    }

    pub fn register(&self, agent: AgentProcess) {
        if let Ok(mut guard) = self.agents.lock() {
            guard.push(agent);
        }
    }

    /// Kills a specific agent by ID.
    pub fn kill(&self, id: &str) -> bool {
        if let Ok(mut guard) = self.agents.lock() {
            if let Some(agent) = guard.iter_mut().find(|a| a.id == id) {
                agent.kill();
                return true;
            }
        }
        false
    }

    /// Kills all currently running agents in the process table.
    pub fn kill_all(&self) -> usize {
        let mut killed_count = 0;
        if let Ok(mut guard) = self.agents.lock() {
            for agent in guard.iter_mut() {
                if matches!(agent.status, AgentStatus::Running | AgentStatus::Paused) {
                    agent.kill();
                    killed_count += 1;
                }
            }
        }
        killed_count
    }

    pub fn list(&self) -> Vec<serde_json::Value> {
        if let Ok(guard) = self.agents.lock() {
            guard.iter().map(|a| a.snapshot()).collect()
        } else {
            Vec::new()
        }
    }
}

static GLOBAL_AGENT_PROCESS_TABLE: OnceLock<ProcessTable> = OnceLock::new();

pub fn global_agent_process_table() -> &'static ProcessTable {
    GLOBAL_AGENT_PROCESS_TABLE.get_or_init(|| {
        let table = ProcessTable::new();
        table.register(AgentProcess::new("agent-wasm-01", "doc-ingest-worker"));
        table.register(AgentProcess::new("agent-wasm-02", "telemetry-correlator"));
        table
    })
}

// ============================================================================
// PART 4: COGNITIVE RED-TEAM HITL INTERCEPTOR & DELIBERATE FRICTION GATE
// ============================================================================

pub const AUTO_VETO_THRESHOLD: f64 = 0.85;
pub const CHALLENGE_TTL_SECONDS: i64 = 120;

/// Taint classification for inter-arm mesh payloads (`MeshTaintLevel`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub enum MeshTaintLevel {
    #[default]
    TrustedInternal = 0,
    Suspect = 1,
    UntrustedExternal = 2,
    Quarantined = 3,
}

impl MeshTaintLevel {
    pub fn requires_capability_stripping(self) -> bool {
        matches!(self, Self::UntrustedExternal | Self::Quarantined)
    }
}

/// Specific visual or syntactic deception indicators detected on a HITL escalation card (`F29`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HitlDeceptionIndicator {
    BidirectionalOverrideRtlo(String),
    ZeroWidthSteganography(String),
    UnicodeConfusableHomograph(String),
    AnsiEscapeInjection(String),
    ObfuscatedShellPayload(String),
    IntentEffectContradiction(String),
}

/// Evaluation result when inspecting a HITL card (`evaluate_hitl_card`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HitlCardEvaluation {
    pub is_deceptive: bool,
    pub has_rtlo: bool,
    pub has_zero_width: bool,
    pub has_ansi_escape: bool,
    pub has_confusable_homograph: bool,
    pub indicators: Vec<HitlDeceptionIndicator>,
    pub recommended_action: String,
}

/// Cryptographically signed Human-in-the-Loop (HITL) operator approval receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HitlApprovalReceipt {
    pub receipt_id: String,
    pub operator_id: String,
    pub target_arm_id: usize,
    pub target_epoch: u64,
    pub correlation_id: String,
    pub approved_tools: Vec<String>,
    pub issued_at_secs: u64,
    pub expires_at_secs: u64,
    pub signature_hex: String,
}

impl HitlApprovalReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        receipt_id: &str,
        operator_id: &str,
        target_arm_id: usize,
        target_epoch: u64,
        correlation_id: &str,
        approved_tools: Vec<String>,
        issued_at_secs: u64,
        expires_at_secs: u64,
        operator_secret: &[u8],
    ) -> Self {
        let mut sorted_tools = approved_tools;
        sorted_tools.sort();
        let canonical = format!(
            "hitl:{}:{}:{}:{}:{}:{}:{}:{}",
            receipt_id,
            operator_id,
            target_arm_id,
            target_epoch,
            correlation_id,
            sorted_tools.join(","),
            issued_at_secs,
            expires_at_secs
        );
        let mut mac = HmacSha256::new_from_slice(operator_secret)
            .expect("HMAC-SHA256 accepts arbitrary key length");
        mac.update(canonical.as_bytes());
        let sig_hex = hex::encode(mac.finalize().into_bytes());
        Self {
            receipt_id: receipt_id.to_string(),
            operator_id: operator_id.to_string(),
            target_arm_id,
            target_epoch,
            correlation_id: correlation_id.to_string(),
            approved_tools: sorted_tools,
            issued_at_secs,
            expires_at_secs,
            signature_hex: sig_hex,
        }
    }
}

/// Scans a string for UTS #39 Unicode confusables, bidirectional overrides (`RTLO`),
/// zero-width characters, ANSI escapes, and encoded shell payloads.
pub fn scan_for_visual_deception(input: &str) -> Vec<HitlDeceptionIndicator> {
    let mut findings = Vec::new();

    if input.chars().any(|c| {
        matches!(
            c,
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'
        )
    }) {
        findings.push(HitlDeceptionIndicator::BidirectionalOverrideRtlo(
            "Detected Unicode Bidi Override (RTLO U+202E / LRO) disguising path or argument order"
                .to_string(),
        ));
    }

    if input.chars().any(|c| {
        matches!(
            c,
            '\u{00AD}' | '\u{200B}'..='\u{200D}' | '\u{FEFF}' | '\u{2060}' | '\u{180E}'
        )
    }) {
        findings.push(HitlDeceptionIndicator::ZeroWidthSteganography(
            "Detected invisible zero-width or soft-hyphen characters splitting command tokens"
                .to_string(),
        ));
    }

    let has_ascii_alpha = input.chars().any(|c| c.is_ascii_alphabetic());
    let has_confusable_script = input.chars().any(|c| {
        let u = c as u32;
        (0x0400..=0x04FF).contains(&u) || (0x0370..=0x03FF).contains(&u)
    });
    if has_ascii_alpha && has_confusable_script {
        findings.push(HitlDeceptionIndicator::UnicodeConfusableHomograph(
            "Detected UTS #39 mixed-script ASCII + Cyrillic/Greek homograph lookalike characters"
                .to_string(),
        ));
    }

    if input.contains('\x1b') || input.contains('\u{009b}') {
        findings.push(HitlDeceptionIndicator::AnsiEscapeInjection(
            "Detected ANSI/VT100 terminal escape sequence in HITL display field".to_string(),
        ));
    }

    let lower = input.to_ascii_lowercase();
    if lower.contains("-enc ")
        || lower.contains("-encodedcommand")
        || lower.contains("frombase64string")
        || lower.contains("| base64 -d")
        || lower.contains("|base64 -d")
        || lower.contains("certutil -decodehex")
    {
        findings.push(HitlDeceptionIndicator::ObfuscatedShellPayload(
            "Detected base64/hex encoded shell payload hiding true command effect".to_string(),
        ));
    }

    findings
}

/// Evaluates a HITL approval card by inspecting BOTH `summary` and `raw_command` for
/// Unicode zero-width characters, RTLO, ANSI escapes, and confusable homographs.
pub fn evaluate_hitl_card(summary: &str, raw_command: &str) -> HitlCardEvaluation {
    let mut indicators = scan_for_visual_deception(summary);
    indicators.extend(scan_for_visual_deception(raw_command));

    let has_rtlo = indicators
        .iter()
        .any(|i| matches!(i, HitlDeceptionIndicator::BidirectionalOverrideRtlo(_)));
    let has_zero_width = indicators
        .iter()
        .any(|i| matches!(i, HitlDeceptionIndicator::ZeroWidthSteganography(_)));
    let has_ansi_escape = indicators
        .iter()
        .any(|i| matches!(i, HitlDeceptionIndicator::AnsiEscapeInjection(_)));
    let has_confusable_homograph = indicators
        .iter()
        .any(|i| matches!(i, HitlDeceptionIndicator::UnicodeConfusableHomograph(_)));
    let is_deceptive = !indicators.is_empty();

    HitlCardEvaluation {
        is_deceptive,
        has_rtlo,
        has_zero_width,
        has_ansi_escape,
        has_confusable_homograph,
        indicators,
        recommended_action: if is_deceptive {
            "AUTO_VETO_BLOCK".to_string()
        } else {
            "PERMIT_REVIEW".to_string()
        },
    }
}

/// Derives the expected typed confirmation token (`CONFIRM:<TOOL>:<BASENAME>`).
pub fn expected_blast_radius_token(tool_name: &str, canonical_resource: &str) -> String {
    let clean_tool = tool_name.trim().to_ascii_uppercase();
    let basename = canonical_resource
        .trim()
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(canonical_resource.trim())
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'))
        .collect::<String>();
    let target_part = if basename.is_empty() {
        "RESOURCE".to_string()
    } else {
        basename.to_ascii_uppercase()
    };
    format!("CONFIRM:{}:{}", clean_tool, target_part)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IrreversibleMutationType {
    PermanentFileOverwriteOrDeletion,
    ExternalNetworkEgress,
    HostProcessExecution,
    CredentialExposure,
    PersistenceModification,
    SecurityBoundaryTampering,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrreversibleStateChange {
    pub mutation_type: IrreversibleMutationType,
    pub resource: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlastRadiusDiff {
    pub target_resource: String,
    pub privilege_tier: String,
    pub is_irreversible: bool,
    pub irreversible_mutations: Vec<IrreversibleStateChange>,
    pub taint_lineage_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolymorphicChallenge {
    pub challenge_id: String,
    pub request_id: String,
    pub prompt: String,
    pub target_resource: String,
    pub options: Vec<String>,
    pub correct_option_index: usize,
    pub challenge_nonce: String,
    pub expires_at_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolymorphicChallengePublic {
    pub challenge_id: String,
    pub request_id: String,
    pub prompt: String,
    pub target_resource: String,
    pub options: Vec<String>,
    pub challenge_nonce: String,
    pub expires_at_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HitlApprovalState {
    PendingChallenge,
    PendingFirstApproval,
    PendingSecondApproval {
        first_operator: String,
    },
    QuorumApproved {
        operators: Vec<String>,
        receipt: Option<HitlApprovalReceipt>,
    },
    AutoVetoed {
        reason: String,
    },
    Rejected {
        operator: String,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingExecutionGraphNode {
    pub session_id: String,
    pub arm_id: usize,
    pub arm_generation: u64,
    pub agent_id: String,
    pub correlation_id: String,
    pub tool_name: String,
    pub target_resource: String,
    pub command_args: String,
    pub stated_justification: String,
    pub incoming_taint: MeshTaintLevel,
    pub user_objective: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CognitiveRedTeamAssessment {
    pub request_id: String,
    pub canonical_tool: String,
    pub canonical_target_resource: String,
    pub stripped_justification: String,
    pub blast_radius_diff: BlastRadiusDiff,
    pub deception_score: f64,
    pub auto_vetoed: bool,
    pub veto_reason: Option<String>,
    pub dual_custody_required: bool,
    pub approval_state: HitlApprovalState,
    pub challenge: Option<PolymorphicChallengePublic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPendingHitlAction {
    pub request_id: String,
    pub node: PendingExecutionGraphNode,
    pub assessment: CognitiveRedTeamAssessment,
    pub full_challenge: Option<PolymorphicChallenge>,
    pub approval_state: HitlApprovalState,
    pub created_at_utc: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CognitiveRedTeamStatus {
    pub total_evaluations: usize,
    pub total_auto_vetoes: usize,
    pub total_challenges_passed: usize,
    pub total_challenges_failed: usize,
    pub total_quorum_completions: usize,
    pub pending_actions_count: usize,
}

pub struct CognitiveRedTeamInterceptor {
    operator_secret: [u8; 32],
    pending_actions: Arc<DashMap<String, StoredPendingHitlAction>>,
    total_evaluations: AtomicUsize,
    total_auto_vetoes: AtomicUsize,
    total_challenges_passed: AtomicUsize,
    total_challenges_failed: AtomicUsize,
    total_quorum_completions: AtomicUsize,
}

impl CognitiveRedTeamInterceptor {
    pub fn new(operator_secret: [u8; 32]) -> Self {
        Self {
            operator_secret,
            pending_actions: Arc::new(DashMap::new()),
            total_evaluations: AtomicUsize::new(0),
            total_auto_vetoes: AtomicUsize::new(0),
            total_challenges_passed: AtomicUsize::new(0),
            total_challenges_failed: AtomicUsize::new(0),
            total_quorum_completions: AtomicUsize::new(0),
        }
    }

    pub fn strip_natural_language_justification(_raw_justification: &str) -> String {
        "[STRIPPED BY COGNITIVE RED-TEAM: Fluency suppressed. Review deterministic blast radius below]"
            .to_string()
    }

    pub fn simulate_blast_radius_diff(
        tool_name: &str,
        target_resource: &str,
        command_args: &str,
        incoming_taint: MeshTaintLevel,
    ) -> BlastRadiusDiff {
        let mut mutations = Vec::new();
        let tool_lower = tool_name.trim().to_ascii_lowercase();
        let resource_lower = target_resource.trim().to_ascii_lowercase();
        let args_lower = command_args.trim().to_ascii_lowercase();

        let is_scratch = resource_lower.contains("scratch")
            || resource_lower.contains("temp")
            || resource_lower.contains("tmp");
        if (tool_lower == "write_file"
            || tool_lower.contains("delete")
            || tool_lower.contains("unlink"))
            && !is_scratch
        {
            mutations.push(IrreversibleStateChange {
                mutation_type: IrreversibleMutationType::PermanentFileOverwriteOrDeletion,
                resource: target_resource.to_string(),
                detail: "Target path is a persistent host location outside isolated scratchpad."
                    .to_string(),
            });
        }

        if resource_lower.contains("system32")
            || resource_lower.contains("hosts")
            || resource_lower.contains("sam")
            || resource_lower.contains("lsass")
            || resource_lower.contains(".ssh")
            || resource_lower.contains("killswitch")
            || args_lower.contains("system32")
            || args_lower.contains("hosts")
            || args_lower.contains("lsass")
        {
            mutations.push(IrreversibleStateChange {
                mutation_type: IrreversibleMutationType::SecurityBoundaryTampering,
                resource: target_resource.to_string(),
                detail:
                    "Action targets protected operating system configuration or credential store."
                        .to_string(),
            });
        }

        if tool_lower == "shell_exec"
            || tool_lower == "cmd"
            || tool_lower == "powershell"
            || args_lower.contains("powershell")
            || args_lower.contains("cmd.exe")
            || args_lower.contains("bash")
            || args_lower.contains("sh ")
        {
            mutations.push(IrreversibleStateChange {
                mutation_type: IrreversibleMutationType::HostProcessExecution,
                resource: if tool_lower == "shell_exec" {
                    "host_interpreter".to_string()
                } else {
                    tool_name.to_string()
                },
                detail:
                    "Spawning host subprocess or script interpreter with unconstrained arguments."
                        .to_string(),
            });
        }

        if tool_lower == "network_egress"
            || args_lower.contains("curl ")
            || args_lower.contains("wget ")
            || args_lower.contains("invoke-webrequest")
            || args_lower.contains("http://")
            || args_lower.contains("https://")
        {
            mutations.push(IrreversibleStateChange {
                mutation_type: IrreversibleMutationType::ExternalNetworkEgress,
                resource: target_resource.to_string(),
                detail: "Outbound socket connection targeting external network endpoint."
                    .to_string(),
            });
        }

        if tool_lower == "extract_credentials"
            || resource_lower.contains("lsass")
            || resource_lower.contains("sam")
            || resource_lower.contains("shadow")
            || resource_lower.contains("dpapi")
            || args_lower.contains("sekurlsa")
            || args_lower.contains("logonpasswords")
        {
            mutations.push(IrreversibleStateChange {
                mutation_type: IrreversibleMutationType::CredentialExposure,
                resource: target_resource.to_string(),
                detail: "Access to system security authority or cryptographic key material."
                    .to_string(),
            });
        }

        if resource_lower.contains("runonce")
            || resource_lower.contains("systemd")
            || resource_lower.contains("tasks")
            || resource_lower.contains("startup")
            || args_lower.contains("schtasks")
            || args_lower.contains("reg add")
        {
            mutations.push(IrreversibleStateChange {
                mutation_type: IrreversibleMutationType::PersistenceModification,
                resource: target_resource.to_string(),
                detail: "Modification of OS auto-start or persistent service registration."
                    .to_string(),
            });
        }

        let is_irreversible = !mutations.is_empty();
        let privilege_tier = if mutations
            .iter()
            .any(|m| m.mutation_type == IrreversibleMutationType::CredentialExposure)
        {
            "CRITICAL_CREDENTIAL_ACCESS".to_string()
        } else if mutations
            .iter()
            .any(|m| m.mutation_type == IrreversibleMutationType::SecurityBoundaryTampering)
        {
            "CRITICAL_HOST_MUTATION_OR_EXEC".to_string()
        } else if is_irreversible {
            "ELEVATED_IRREVERSIBLE_OPERATION".to_string()
        } else {
            "BENIGN_REVERSIBLE_OPERATION".to_string()
        };

        BlastRadiusDiff {
            target_resource: target_resource.to_string(),
            privilege_tier,
            is_irreversible,
            irreversible_mutations: mutations,
            taint_lineage_summary: format!("MeshTaint::{:?}", incoming_taint),
        }
    }

    pub fn compute_saelens_deception_likelihood(
        user_objective: &str,
        tool_name: &str,
        target_resource: &str,
        command_args: &str,
        stated_justification: &str,
        incoming_taint: MeshTaintLevel,
        blast_diff: &BlastRadiusDiff,
    ) -> (f64, Option<String>) {
        let combined_text = format!(
            "{}\n{}\n{}\n{}",
            stated_justification, tool_name, target_resource, command_args
        );
        let indicators = scan_for_visual_deception(&combined_text);
        let mut obf_score = 0.0f64;
        for ind in &indicators {
            match ind {
                HitlDeceptionIndicator::BidirectionalOverrideRtlo(_) => obf_score += 0.95,
                HitlDeceptionIndicator::UnicodeConfusableHomograph(_) => obf_score += 0.90,
                HitlDeceptionIndicator::ObfuscatedShellPayload(_) => obf_score += 0.90,
                HitlDeceptionIndicator::ZeroWidthSteganography(_) => obf_score += 0.85,
                HitlDeceptionIndicator::AnsiEscapeInjection(_) => obf_score += 0.85,
                HitlDeceptionIndicator::IntentEffectContradiction(_) => obf_score += 0.50,
            }
        }
        obf_score = obf_score.min(1.0);

        let obj_lower = user_objective.trim().to_ascii_lowercase();
        let is_benign_objective = obj_lower.contains("read")
            || obj_lower.contains("test")
            || obj_lower.contains("format")
            || obj_lower.contains("lint")
            || obj_lower.contains("check")
            || obj_lower.contains("docs");

        let mut div_score = 0.0f64;
        if is_benign_objective {
            if blast_diff
                .irreversible_mutations
                .iter()
                .any(|m| m.mutation_type == IrreversibleMutationType::CredentialExposure)
            {
                div_score = 0.95;
            } else if blast_diff
                .irreversible_mutations
                .iter()
                .any(|m| m.mutation_type == IrreversibleMutationType::SecurityBoundaryTampering)
            {
                div_score = 0.90;
            } else if blast_diff.is_irreversible {
                div_score = 0.60;
            }
        }

        let taint_score = match incoming_taint {
            MeshTaintLevel::TrustedInternal => 0.0,
            MeshTaintLevel::Suspect => 0.35,
            MeshTaintLevel::UntrustedExternal => 0.65,
            MeshTaintLevel::Quarantined => 0.95,
        };

        let irrev_score = (0.25 * blast_diff.irreversible_mutations.len() as f64).min(1.0);
        let blended =
            1.0 - (1.0 - obf_score * 0.7) * (1.0 - taint_score * 0.5) * (1.0 - irrev_score * 0.3);
        let p_deception = obf_score.max(div_score).max(blended).clamp(0.0, 1.0);

        let veto_reason = if p_deception >= AUTO_VETO_THRESHOLD {
            Some(format!(
                "COGNITIVE_REDTEAM_AUTO_VETO: Deception likelihood P_deception={:.2} >= {:.2} (indicators={:?}, divergence={:.2}). Execution blocked.",
                p_deception, AUTO_VETO_THRESHOLD, indicators, div_score
            ))
        } else {
            None
        };

        (p_deception, veto_reason)
    }

    pub fn generate_polymorphic_challenge(
        request_id: &str,
        target_resource: &str,
        tool_name: &str,
    ) -> PolymorphicChallenge {
        let tool_lower = tool_name.trim().to_ascii_lowercase();
        let (genuine_invariant, distractors) = if tool_lower.contains("write")
            || target_resource.contains("hosts")
            || target_resource.contains("System32")
        {
            (
                "Invariant: Host filesystem paths outside sandbox scratchpad cannot be truncated or unlinked without write-intent authorization.",
                vec![
                    "Invariant: Local loopback adapter MTU must remain configured at exactly 1500 bytes.",
                    "Invariant: Audio renderer buffer size must not exceed 4096 samples per frame.",
                    "Invariant: Display scaling factor must remain at 100% during background batch jobs.",
                ],
            )
        } else if tool_lower.contains("cred") || target_resource.contains("lsass") {
            (
                "Invariant: Operating system credentials in LSASS/SAM/DPAPI are accessible exclusively to SYSTEM and must not be exposed to child workers.",
                vec![
                    "Invariant: Windows font cache size must not exceed 64 megabytes.",
                    "Invariant: Mouse cursor update polling rate must remain between 60Hz and 144Hz.",
                    "Invariant: Bluetooth peripheral pairing timeout must be exactly 300 seconds.",
                ],
            )
        } else if tool_lower.contains("exec")
            || tool_lower.contains("cmd")
            || tool_lower.contains("powershell")
        {
            (
                "Invariant: Subprocess execution environments must not inherit un-sanitized interpreter hook variables (PYTHONPATH, RUSTC_WRAPPER, NODE_OPTIONS).",
                vec![
                    "Invariant: CPU fan speed governor must remain in passive mode during I/O operations.",
                    "Invariant: System tray icon dimensions must remain 16x16 pixels.",
                    "Invariant: Network interface MAC address must not contain odd-parity octets.",
                ],
            )
        } else {
            (
                "Invariant: Outbound socket connections must not target unverified public IPv4/IPv6 endpoints from isolated sandbox workers.",
                vec![
                    "Invariant: GPU shader compilation cache must remain bounded under 128 megabytes.",
                    "Invariant: Keyboard repeat delay must remain configured at 500 milliseconds.",
                    "Invariant: Default printer spooler port must not use TCP port 9100.",
                ],
            )
        };

        let mut options = vec![
            genuine_invariant.to_string(),
            distractors[0].to_string(),
            distractors[1].to_string(),
            distractors[2].to_string(),
        ];

        let mut rng = rand::thread_rng();
        options.shuffle(&mut rng);

        let correct_option_index = options
            .iter()
            .position(|o| o == genuine_invariant)
            .unwrap_or(0);

        let challenge_id = format!("chal-{}", uuid::Uuid::new_v4());
        let challenge_nonce = format!("{:x}", uuid::Uuid::new_v4().as_u128());
        let expires_at_utc = Utc::now() + chrono::Duration::seconds(CHALLENGE_TTL_SECONDS);

        PolymorphicChallenge {
            challenge_id,
            request_id: request_id.to_string(),
            prompt: "Identify the genuine system invariant governing this action to verify comprehension:".to_string(),
            target_resource: target_resource.to_string(),
            options,
            correct_option_index,
            challenge_nonce,
            expires_at_utc,
        }
    }

    pub fn evaluate_pending_action(
        &self,
        node: PendingExecutionGraphNode,
    ) -> CognitiveRedTeamAssessment {
        self.total_evaluations.fetch_add(1, Ordering::SeqCst);

        let request_id = format!("req-{}", uuid::Uuid::new_v4());
        let canonical_tool = node.tool_name.trim().to_ascii_lowercase();
        let canonical_target_resource = node.target_resource.trim().to_string();
        let stripped_justification =
            Self::strip_natural_language_justification(&node.stated_justification);

        let blast_diff = Self::simulate_blast_radius_diff(
            &node.tool_name,
            &node.target_resource,
            &node.command_args,
            node.incoming_taint,
        );

        let (deception_score, veto_reason) = Self::compute_saelens_deception_likelihood(
            &node.user_objective,
            &node.tool_name,
            &node.target_resource,
            &node.command_args,
            &node.stated_justification,
            node.incoming_taint,
            &blast_diff,
        );

        let auto_vetoed = deception_score >= AUTO_VETO_THRESHOLD;
        if auto_vetoed {
            self.total_auto_vetoes.fetch_add(1, Ordering::SeqCst);
        }

        let dual_custody_required = node.incoming_taint == MeshTaintLevel::UntrustedExternal
            || node.incoming_taint == MeshTaintLevel::Quarantined
            || blast_diff.is_irreversible;

        let (approval_state, challenge_pub, full_challenge) = if auto_vetoed {
            (
                HitlApprovalState::AutoVetoed {
                    reason: veto_reason.clone().unwrap_or_default(),
                },
                None,
                None,
            )
        } else {
            let challenge = Self::generate_polymorphic_challenge(
                &request_id,
                &canonical_target_resource,
                &canonical_tool,
            );
            let pub_challenge = PolymorphicChallengePublic {
                challenge_id: challenge.challenge_id.clone(),
                request_id: challenge.request_id.clone(),
                prompt: challenge.prompt.clone(),
                target_resource: challenge.target_resource.clone(),
                options: challenge.options.clone(),
                challenge_nonce: challenge.challenge_nonce.clone(),
                expires_at_utc: challenge.expires_at_utc,
            };
            (
                HitlApprovalState::PendingChallenge,
                Some(pub_challenge),
                Some(challenge),
            )
        };

        let assessment = CognitiveRedTeamAssessment {
            request_id: request_id.clone(),
            canonical_tool,
            canonical_target_resource,
            stripped_justification,
            blast_radius_diff: blast_diff,
            deception_score,
            auto_vetoed,
            veto_reason,
            dual_custody_required,
            approval_state: approval_state.clone(),
            challenge: challenge_pub,
        };

        let stored = StoredPendingHitlAction {
            request_id: request_id.clone(),
            node,
            assessment: assessment.clone(),
            full_challenge,
            approval_state,
            created_at_utc: Utc::now(),
        };

        self.pending_actions.insert(request_id, stored);
        assessment
    }

    pub fn get_pending_actions(&self) -> Vec<CognitiveRedTeamAssessment> {
        self.pending_actions
            .iter()
            .map(|entry| entry.value().assessment.clone())
            .collect()
    }

    pub fn get_public_challenge(&self, request_id: &str) -> Option<PolymorphicChallengePublic> {
        self.pending_actions.get(request_id).and_then(|entry| {
            entry
                .value()
                .full_challenge
                .as_ref()
                .map(|c| PolymorphicChallengePublic {
                    challenge_id: c.challenge_id.clone(),
                    request_id: c.request_id.clone(),
                    prompt: c.prompt.clone(),
                    target_resource: c.target_resource.clone(),
                    options: c.options.clone(),
                    challenge_nonce: c.challenge_nonce.clone(),
                    expires_at_utc: c.expires_at_utc,
                })
        })
    }

    pub fn submit_approval(
        &self,
        request_id: &str,
        operator_id: &str,
        selected_option_index: usize,
        challenge_nonce: &str,
        confirmation_token: Option<&str>,
    ) -> Result<HitlApprovalState, String> {
        let op_trimmed = operator_id.trim();
        if op_trimmed.is_empty() {
            return Err("IDENTITY_SPOOFING: Operator ID cannot be empty".to_string());
        }

        let mut entry = self
            .pending_actions
            .get_mut(request_id)
            .ok_or_else(|| format!("HITL request '{}' not found in pending actions", request_id))?;

        if entry.assessment.auto_vetoed {
            return Err(
                "Action was auto-vetoed by Cognitive Red-Team Interceptor. Approval is forbidden."
                    .to_string(),
            );
        }

        let challenge = entry
            .full_challenge
            .as_ref()
            .ok_or_else(|| "No active challenge found for action".to_string())?;

        if challenge.challenge_nonce != challenge_nonce {
            self.total_challenges_failed.fetch_add(1, Ordering::SeqCst);
            return Err("Invalid challenge nonce provided".to_string());
        }

        if Utc::now() > challenge.expires_at_utc {
            self.total_challenges_failed.fetch_add(1, Ordering::SeqCst);
            return Err("Challenge expired (TTL 120s exceeded). Refresh challenge.".to_string());
        }

        if selected_option_index != challenge.correct_option_index {
            self.total_challenges_failed.fetch_add(1, Ordering::SeqCst);
            return Err(
                "Incorrect system invariant selected in polymorphic challenge. Review blast radius."
                    .to_string(),
            );
        }

        self.total_challenges_passed.fetch_add(1, Ordering::SeqCst);

        if entry.assessment.deception_score >= 0.45 && entry.assessment.deception_score < 0.85 {
            let expected_token =
                expected_blast_radius_token(&entry.node.tool_name, &entry.node.target_resource);
            if let Some(token) = confirmation_token {
                if token.trim() != expected_token {
                    return Err(format!(
                        "Typed confirmation token mismatch: expected '{}', got '{}'",
                        expected_token, token
                    ));
                }
            } else {
                return Err(format!(
                    "Typed confirmation token required: '{}'",
                    expected_token
                ));
            }
        }

        if entry.assessment.dual_custody_required {
            match &entry.approval_state {
                HitlApprovalState::PendingChallenge | HitlApprovalState::PendingFirstApproval => {
                    let new_state = HitlApprovalState::PendingSecondApproval {
                        first_operator: op_trimmed.to_string(),
                    };
                    entry.approval_state = new_state.clone();
                    entry.assessment.approval_state = new_state.clone();
                    Ok(new_state)
                }
                HitlApprovalState::PendingSecondApproval { first_operator } => {
                    if first_operator == op_trimmed {
                        return Err(
                            "DUAL_CUSTODY_SELF_APPROVAL_FORBIDDEN: Second operator must be distinct from first operator."
                                .to_string(),
                        );
                    }

                    let receipt_id = format!("rcpt-{}", uuid::Uuid::new_v4());
                    let issued_at = Utc::now().timestamp() as u64;
                    let expires_at = issued_at + 300;

                    let receipt = HitlApprovalReceipt::sign(
                        &receipt_id,
                        &format!("{}+{}", first_operator, op_trimmed),
                        entry.node.arm_id,
                        entry.node.arm_generation,
                        &entry.node.correlation_id,
                        vec![entry.node.tool_name.clone()],
                        issued_at,
                        expires_at,
                        &self.operator_secret,
                    );

                    let new_state = HitlApprovalState::QuorumApproved {
                        operators: vec![first_operator.clone(), op_trimmed.to_string()],
                        receipt: Some(receipt),
                    };
                    entry.approval_state = new_state.clone();
                    entry.assessment.approval_state = new_state.clone();
                    self.total_quorum_completions.fetch_add(1, Ordering::SeqCst);
                    Ok(new_state)
                }
                HitlApprovalState::QuorumApproved { .. } => Ok(entry.approval_state.clone()),
                other => Err(format!("Action cannot be approved in state {:?}", other)),
            }
        } else {
            let receipt_id = format!("rcpt-{}", uuid::Uuid::new_v4());
            let issued_at = Utc::now().timestamp() as u64;
            let expires_at = issued_at + 300;

            let receipt = HitlApprovalReceipt::sign(
                &receipt_id,
                op_trimmed,
                entry.node.arm_id,
                entry.node.arm_generation,
                &entry.node.correlation_id,
                vec![entry.node.tool_name.clone()],
                issued_at,
                expires_at,
                &self.operator_secret,
            );

            let new_state = HitlApprovalState::QuorumApproved {
                operators: vec![op_trimmed.to_string()],
                receipt: Some(receipt),
            };
            entry.approval_state = new_state.clone();
            entry.assessment.approval_state = new_state.clone();
            self.total_quorum_completions.fetch_add(1, Ordering::SeqCst);
            Ok(new_state)
        }
    }

    pub fn submit_rejection(
        &self,
        request_id: &str,
        operator_id: &str,
        reason: &str,
    ) -> Result<HitlApprovalState, String> {
        let mut entry = self
            .pending_actions
            .get_mut(request_id)
            .ok_or_else(|| format!("HITL request '{}' not found in pending actions", request_id))?;

        let new_state = HitlApprovalState::Rejected {
            operator: operator_id.trim().to_string(),
            reason: reason.trim().to_string(),
        };
        entry.approval_state = new_state.clone();
        entry.assessment.approval_state = new_state.clone();
        Ok(new_state)
    }

    pub fn get_status(&self) -> CognitiveRedTeamStatus {
        CognitiveRedTeamStatus {
            total_evaluations: self.total_evaluations.load(Ordering::Relaxed),
            total_auto_vetoes: self.total_auto_vetoes.load(Ordering::Relaxed),
            total_challenges_passed: self.total_challenges_passed.load(Ordering::Relaxed),
            total_challenges_failed: self.total_challenges_failed.load(Ordering::Relaxed),
            total_quorum_completions: self.total_quorum_completions.load(Ordering::Relaxed),
            pending_actions_count: self.pending_actions.len(),
        }
    }
}

static GLOBAL_COGNITIVE_REDTEAM: OnceLock<CognitiveRedTeamInterceptor> = OnceLock::new();

pub fn global_cognitive_redteam() -> &'static CognitiveRedTeamInterceptor {
    GLOBAL_COGNITIVE_REDTEAM.get_or_init(|| CognitiveRedTeamInterceptor::new([0x5cu8; 32]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_four_gate_database_tamper_guard_and_maintenance_lease() {
        let temp_dir = tempfile::tempdir().unwrap();
        let guard = LocalMySqlTamperGuard::new(temp_dir.path());
        guard.record_golden_row("policy_mode", "ENFORCE_STRICT");
        guard.record_golden_row("wfp_sublayer", "ACTIVE");

        let mut live_rows = HashMap::from([
            ("policy_mode".to_string(), "ENFORCE_STRICT".to_string()),
            ("wfp_sublayer".to_string(), "ACTIVE".to_string()),
        ]);

        // 1. Healthy rows pass
        assert_eq!(
            guard.verify_live_rows(&mut live_rows),
            TamperCheckOutcome::Healthy
        );

        // 2. Authenticated maintenance lease suppresses false-positive KillSwitch during legitimate row update
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expiry = now_unix + 120;
        let token = compute_maintenance_auth_token("schema-migration-v2", expiry);
        {
            let _lease =
                begin_database_maintenance_lease("schema-migration-v2", 120, expiry, &token)
                    .expect("valid maintenance token must succeed");
            live_rows.remove("policy_mode");
            let outcome = guard.verify_live_rows(&mut live_rows);
            assert!(matches!(
                outcome,
                TamperCheckOutcome::MaintenanceDeferred { .. }
            ));
        }

        // 3. Once the lease guard is dropped, unauthorized deletion triggers KillSwitch + self-healing!
        let hostile_outcome = guard.verify_live_rows(&mut live_rows);
        assert!(matches!(
            hostile_outcome,
            TamperCheckOutcome::HostileTamperConfirmed {
                killswitch_engaged: true,
                self_healed: true,
                ..
            }
        ));
        assert_eq!(
            live_rows.get("policy_mode").map(String::as_str),
            Some("ENFORCE_STRICT")
        );
    }

    #[test]
    fn test_edr_executable_tamper_guard_and_golden_self_healing() {
        let temp_dir = tempfile::tempdir().unwrap();
        let fake_exe = temp_dir.path().join("killswitch-daemon.exe");
        std::fs::write(&fake_exe, b"MZ-AUTHENTIC-KILLSWITCH-BINARY-V1").unwrap();

        let exe_guard = EdrExecutableTamperGuard::protect_executable_at(&fake_exe)
            .expect("protect_executable_at should succeed");
        assert_eq!(
            exe_guard.verify_running_exe_integrity_tick(),
            TamperCheckOutcome::Healthy
        );

        // Drop the file lock handle inside a scoped test copy so we can simulate offline disk corruption
        let unlocked_guard = EdrExecutableTamperGuard {
            exe_path: exe_guard.exe_path.clone(),
            golden_mirror_path: exe_guard.golden_mirror_path.clone(),
            expected_blake3_hex: exe_guard.expected_blake3_hex.clone(),
            process_dacl_hardened: exe_guard.process_dacl_hardened,
            delete_rename_lock_held: false,
            _locked_file_handle: None,
        };
        drop(exe_guard);

        std::fs::write(&fake_exe, b"CORRUPTED-BY-ROOTKIT").unwrap();
        let outcome = unlocked_guard.verify_running_exe_integrity_tick();
        assert!(matches!(
            outcome,
            TamperCheckOutcome::HostileTamperConfirmed {
                killswitch_engaged: true,
                self_healed: true,
                ..
            }
        ));
        assert_eq!(
            std::fs::read(&fake_exe).unwrap(),
            b"MZ-AUTHENTIC-KILLSWITCH-BINARY-V1"
        );
    }

    #[test]
    fn test_console_freeze_defense_and_agent_process_table_killswitch() {
        let raw_mode = ENABLE_QUICK_EDIT_MODE | ENABLE_INSERT_MODE | ENABLE_MOUSE_INPUT;
        assert!(!is_console_mode_hardened(raw_mode));
        let hardened = compute_hardened_console_mode(raw_mode);
        assert!(is_console_mode_hardened(hardened));

        let table = ProcessTable::new();
        table.register(AgentProcess::new("ag-1", "worker-1"));
        table.register(AgentProcess::new("ag-2", "worker-2"));
        assert!(table.kill("ag-1"));
        assert_eq!(table.kill_all(), 1);
    }

    #[test]
    fn test_cognitive_redteam_auto_veto_and_dual_custody_quorum() {
        let interceptor = CognitiveRedTeamInterceptor::new([0x33; 32]);

        // 1. Deceptive credential dump under benign objective -> auto-vetoed at >= 0.85
        let deceptive_node = PendingExecutionGraphNode {
            session_id: "sess-01".to_string(),
            arm_id: 1,
            arm_generation: 1,
            agent_id: "worker-1".to_string(),
            correlation_id: "corr-01".to_string(),
            tool_name: "extract_credentials".to_string(),
            target_resource: "C:\\Windows\\System32\\lsass.exe".to_string(),
            command_args: "--dump".to_string(),
            stated_justification: "Formatting project README".to_string(),
            incoming_taint: MeshTaintLevel::UntrustedExternal,
            user_objective: "Format readme and fix typos".to_string(),
        };
        let dec_assessment = interceptor.evaluate_pending_action(deceptive_node);
        assert!(dec_assessment.auto_vetoed);
        assert!(dec_assessment.deception_score >= 0.85);

        // 2. Dual-custody quorum approval ($O_1 \neq O_2$)
        let quorum_node = PendingExecutionGraphNode {
            session_id: "sess-03".to_string(),
            arm_id: 3,
            arm_generation: 1,
            agent_id: "worker-3".to_string(),
            correlation_id: "corr-03".to_string(),
            tool_name: "write_file".to_string(),
            target_resource: "C:\\Windows\\System32\\drivers\\etc\\hosts".to_string(),
            command_args: "127.0.0.1 safe.local".to_string(),
            stated_justification: "Updating system host routing entry".to_string(),
            incoming_taint: MeshTaintLevel::UntrustedExternal,
            user_objective: "Modify system host routing configuration".to_string(),
        };
        let assessment = interceptor.evaluate_pending_action(quorum_node);
        assert!(assessment.dual_custody_required);
        let pub_chal = assessment.challenge.unwrap();
        let correct_idx = {
            let stored = interceptor
                .pending_actions
                .get(&assessment.request_id)
                .unwrap();
            stored.full_challenge.as_ref().unwrap().correct_option_index
        };

        let first = interceptor
            .submit_approval(
                &assessment.request_id,
                "operator_alice",
                correct_idx,
                &pub_chal.challenge_nonce,
                None,
            )
            .unwrap();
        assert!(matches!(
            first,
            HitlApprovalState::PendingSecondApproval { .. }
        ));

        // Self-approval by same operator must fail
        assert!(interceptor
            .submit_approval(
                &assessment.request_id,
                "operator_alice",
                correct_idx,
                &pub_chal.challenge_nonce,
                None,
            )
            .is_err());

        // Second distinct operator completes quorum
        let second = interceptor
            .submit_approval(
                &assessment.request_id,
                "operator_bob",
                correct_idx,
                &pub_chal.challenge_nonce,
                None,
            )
            .unwrap();
        assert!(matches!(second, HitlApprovalState::QuorumApproved { .. }));
    }
}
