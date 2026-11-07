//! # Temporal Circumvention Correlator & Dynamic Denial Observation (Incident A)
//!
//! Implements Milestone SEC-3 (Requirement R6):
//! - Dynamic observation of runtime denial signals (EACCES/EPERM, Linux PAM, Windows UAC, Win32 access denied).
//! - 60-second sliding-window state memory linking initial blocked actions to equivalent retries.
//! - Cross-boundary detection across WSL2 VM and Hyper-V isolation perimeters.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

use crate::semantic_command::{
    parse_semantic_command, PrivilegeEquivalenceClass, SemanticCommand,
};


/// Structured classification of dynamic denial signals observed at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DenialPatternKind {
    /// POSIX filesystem or system call denial (EPERM / EACCES)
    PosixEpermEacces,
    /// Linux PAM authentication failure (su, login)
    LinuxPamAuthFailure,
    /// Sudo password required under non-interactive mode (-n)
    SudoPasswordRequired,
    /// User not present in sudoers file
    SudoersUnauthorized,
    /// Windows UAC elevation cancelled or dismissed (Win32 ERROR_CANCELLED = 1223)
    WindowsUacCancelled,
    /// Windows Win32 ERROR_ACCESS_DENIED (5)
    WindowsAccessDenied,
    /// Windows Win32 ERROR_ELEVATION_REQUIRED (740) or ERROR_PRIVILEGE_NOT_HELD (1314)
    WindowsElevationRequired,
    /// Generic explicit message requiring root or Administrator
    ExplicitRootAdminRequired,
    /// Generic non-zero exit code failure
    GenericNonZeroExit,
}

/// Dynamic denial signal captured at runtime from process execution outcomes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DynamicDenialSignal {
    /// Unique identifier for the denial event
    pub signal_id: String,
    /// Agent session or workspace correlation token
    pub session_id: String,
    /// Parent PID (e.g. Node.js, Python, or shell agent runtime)
    pub parent_pid: Option<u32>,
    /// OS Process ID of the denied executable
    pub pid: u32,
    /// Full command line string that was denied
    pub command_line: String,
    /// Resolved executable binary name or path
    pub executable: String,
    /// Privilege equivalence class evaluated by AST analysis
    pub privilege_class: PrivilegeEquivalenceClass,
    /// Process exit code (if process terminated normally)
    pub exit_code: Option<i32>,
    /// Flag indicating that authorization or permission was explicitly denied
    pub is_permission_denied: bool,
    /// Verbatim matching snippet from standard error
    pub stderr_signature: Option<String>,
    /// Categorized pattern taxonomy
    pub pattern_kind: DenialPatternKind,
    /// High-resolution monotonic timestamp for sliding-window arithmetic
    #[serde(skip, default = "Instant::now")]
    pub timestamp: Instant,
    /// ISO 8601 UTC timestamp for persistence, logging, and audit trails
    pub timestamp_utc: String,
}

impl DynamicDenialSignal {
    /// Direct constructor compatible with `tests/incident_a_reproduction.rs` and E2E suites.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signal_id: impl Into<String>,
        session_id: impl Into<String>,
        parent_pid: Option<u32>,
        pid: u32,
        command_line: impl Into<String>,
        privilege_class: PrivilegeEquivalenceClass,
        exit_code: Option<i32>,
        is_permission_denied: bool,
        stderr_signature: Option<String>,
        timestamp: Instant,
    ) -> Self {
        let cmd_str = command_line.into();
        let exe = cmd_str
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches(['"', '\''])
            .to_string();
        let pattern_kind = classify_denial_pattern(exit_code, stderr_signature.as_deref().unwrap_or(""))
            .map(|(k, _)| k)
            .unwrap_or(DenialPatternKind::GenericNonZeroExit);

        Self {
            signal_id: signal_id.into(),
            session_id: session_id.into(),
            parent_pid,
            pid,
            command_line: cmd_str,
            executable: exe,
            privilege_class,
            exit_code,
            is_permission_denied,
            stderr_signature,
            pattern_kind,
            timestamp,
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Helper returning parent PID as u32 (0 if None) for PROJECT.md contract compatibility.
    pub fn parent_pid_u32(&self) -> u32 {
        self.parent_pid.unwrap_or(0)
    }
}

/// Circumvention alert generated when a temporal retry of a blocked action is detected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CircumventionAlert {
    /// Unique alert identifier (`circ-<id>`)
    pub alert_id: String,
    /// Session identifier of the originating agent execution
    pub session_id: String,
    /// Initial command line that was blocked or denied
    pub initial_blocked_command: String,
    /// Retry command line attempting equivalent elevation or circumvention
    pub retry_command: String,
    /// Milliseconds elapsed between denial and retry
    pub elapsed_millis: u64,
    /// True if retry attempted to cross WSL2 or Hyper-V VM boundary
    pub crossed_wsl_boundary: bool,
    /// Mathematical confidence estimate (0.0 .. 1.0)
    pub confidence: f32,
    /// Severity classification string ("CRITICAL")
    pub severity: &'static str,
    /// Numeric severity code (4 = Critical) for contract compatibility
    pub severity_code: u8,
    /// Human-readable narrative summary
    pub summary: String,
}

/// Evaluates runtime denial outcomes dynamically across POSIX, Linux PAM, and Windows Win32.
///
/// Returns true if execution failed due to lack of elevation, credential requirement,
/// permission denial, or UAC dismissal.
pub fn evaluate_denial_outcome(
    _command_line: &str,
    exit_code: Option<i32>,
    stderr: &str,
) -> bool {
    let Some(code) = exit_code else {
        return false;
    };
    if code == 0 {
        return false;
    }

    // Windows UAC cancellation error code 1223 (ERROR_CANCELLED)
    if code == 1223 {
        return true;
    }

    let stderr_lc = stderr.to_ascii_lowercase();

    // Rejection patterns across Linux PAM, POSIX errno, sudo, and Windows
    if stderr_lc.contains("a password is required")
        || stderr_lc.contains("password is required")
        || stderr_lc.contains("authentication failure")
        || stderr_lc.contains("permission denied")
        || stderr_lc.contains("operation not permitted")
        || stderr_lc.contains("requires elevation")
        || stderr_lc.contains("access is denied")
        || stderr_lc.contains("not in the sudoers file")
        || stderr_lc.contains("incorrect password")
        || stderr_lc.contains("conversation failed")
        || stderr_lc.contains("pam_authenticate failed")
        || stderr_lc.contains("only root can do that")
        || stderr_lc.contains("you must be root")
        || stderr_lc.contains("need to be root")
        || stderr_lc.contains("must be run as root")
        || stderr_lc.contains("root privileges required")
        || stderr_lc.contains("administrator privileges required")
        || stderr_lc.contains("run as administrator")
        || stderr_lc.contains("the operation was canceled by the user")
        || stderr_lc.contains("elevated permissions are required")
        || stderr_lc.contains("privilege is not held")
        || stderr_lc.contains("system error 5 has occurred")
        || stderr_lc.contains("read-only file system")
    {
        return true;
    }

    // Distinct Win32 / POSIX denial exit codes:
    // 5 = ERROR_ACCESS_DENIED, 740 = ERROR_ELEVATION_REQUIRED, 1314 = ERROR_PRIVILEGE_NOT_HELD, 126 = POSIX EACCES
    matches!(code, 5 | 740 | 126 | 1314)
}

/// Classifies stderr and exit code into a structured `DenialPatternKind` and signature snippet.
pub fn classify_denial_pattern(
    exit_code: Option<i32>,
    stderr: &str,
) -> Option<(DenialPatternKind, String)> {
    if exit_code == Some(1223) {
        return Some((
            DenialPatternKind::WindowsUacCancelled,
            "Windows UAC Elevation Cancelled (1223)".to_string(),
        ));
    }

    let stderr_lc = stderr.to_ascii_lowercase();

    if stderr_lc.contains("a password is required") || stderr_lc.contains("password is required") {
        Some((DenialPatternKind::SudoPasswordRequired, "sudo password required".to_string()))
    } else if stderr_lc.contains("authentication failure") || stderr_lc.contains("pam_authenticate failed") {
        Some((DenialPatternKind::LinuxPamAuthFailure, "PAM authentication failure".to_string()))
    } else if stderr_lc.contains("not in the sudoers file") {
        Some((DenialPatternKind::SudoersUnauthorized, "unauthorized in sudoers".to_string()))
    } else if stderr_lc.contains("permission denied") || stderr_lc.contains("operation not permitted") {
        Some((DenialPatternKind::PosixEpermEacces, "POSIX permission denied (EPERM/EACCES)".to_string()))
    } else if stderr_lc.contains("the operation was canceled by the user") {
        Some((DenialPatternKind::WindowsUacCancelled, "UAC prompt cancelled".to_string()))
    } else if stderr_lc.contains("access is denied") || exit_code == Some(5) {
        Some((DenialPatternKind::WindowsAccessDenied, "Windows Access Denied (5)".to_string()))
    } else if stderr_lc.contains("requires elevation") || exit_code == Some(740) || exit_code == Some(1314) {
        Some((DenialPatternKind::WindowsElevationRequired, "Windows Elevation Required".to_string()))
    } else if stderr_lc.contains("must be root") || stderr_lc.contains("only root can do that") || stderr_lc.contains("you must be root") {
        Some((DenialPatternKind::ExplicitRootAdminRequired, "Root/Administrator privileges required".to_string()))
    } else if let Some(code) = exit_code {
        if code != 0 {
            Some((DenialPatternKind::GenericNonZeroExit, format!("Exit code {}", code)))
        } else {
            None
        }
    } else {
        None
    }
}

/// Dynamic observer helper to construct a `DynamicDenialSignal` if execution was denied.
pub fn observe_denial(
    session_id: impl Into<String>,
    parent_pid: Option<u32>,
    pid: u32,
    command_line: impl Into<String>,
    exit_code: Option<i32>,
    stderr: &str,
    timestamp: Instant,
) -> Option<DynamicDenialSignal> {
    let cmd = command_line.into();
    if !evaluate_denial_outcome(&cmd, exit_code, stderr) {
        return None;
    }

    let sem = parse_semantic_command(&cmd);
    let sig_id = format!("sig-{}", uuid::Uuid::new_v4());
    let (pattern_kind, sig_text) = classify_denial_pattern(exit_code, stderr)
        .unwrap_or((DenialPatternKind::GenericNonZeroExit, stderr.trim().to_string()));

    Some(DynamicDenialSignal {
        signal_id: sig_id,
        session_id: session_id.into(),
        parent_pid,
        pid,
        command_line: cmd,
        executable: sem.executable,
        privilege_class: sem.privilege_class,
        exit_code,
        is_permission_denied: true,
        stderr_signature: Some(sig_text),
        pattern_kind,
        timestamp,
        timestamp_utc: chrono::Utc::now().to_rfc3339(),
    })
}

/// Helper detecting cross-boundary invocation across WSL2 VM, Hyper-V, and container namespaces.
pub fn is_cross_boundary_invocation(raw_command: &str, sem: &SemanticCommand) -> bool {
    if sem.is_cross_boundary {
        return true;
    }
    if let Some(ref probe) = sem.dynamic_probe {
        if probe.invokes_wsl_subsystem || probe.invokes_hyperv_compute {
            return true;
        }
    }
    let lower = raw_command.to_ascii_lowercase();
    if lower.contains("wsl.exe") || lower.contains("wsl ") || lower.starts_with("wsl") {
        return true;
    }
    if lower.contains("vmcompute") || lower.contains("hcsdiag") || lower.contains("vmconnect") {
        return true;
    }
    if lower.contains("-vmname") || lower.contains("hyper-v") {
        return true;
    }
    false
}

/// Temporal Circumvention Correlator maintaining sliding-window state memory.
pub struct TemporalCircumventionCorrelator {
    sliding_window: Duration,
    denials: Mutex<VecDeque<DynamicDenialSignal>>,
    alert_counter: AtomicU64,
}

/// Type alias for 100% drop-in compatibility with `tests/incident_a_reproduction.rs`.
pub type TemporalCircumventionEngine = TemporalCircumventionCorrelator;

impl Default for TemporalCircumventionCorrelator {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}

impl TemporalCircumventionCorrelator {
    /// Constructs a new correlator with specified sliding-window retention (e.g. 60 seconds).
    pub fn new(sliding_window: Duration) -> Self {
        Self {
            sliding_window,
            denials: Mutex::new(VecDeque::new()),
            alert_counter: AtomicU64::new(1),
        }
    }

    /// Records an observed dynamic denial signal into temporal state memory.
    pub fn record_denial(&self, signal: DynamicDenialSignal) {
        let mut guard = self.denials.lock().unwrap();
        let now = Instant::now();
        guard.retain(|d| {
            now.checked_duration_since(d.timestamp)
                .map(|dur| dur <= self.sliding_window)
                .unwrap_or(false)
        });
        if guard.len() >= 1024 {
            guard.pop_front();
        }
        guard.push_back(signal);
    }

    /// Evaluates candidate command execution against active sliding-window denial memory.
    ///
    /// Correlates by session_id OR shared parent_pid (agent process runtime).
    pub fn check_candidate(
        &self,
        session_id: &str,
        parent_pid: Option<u32>,
        command_line: &str,
        now: Instant,
    ) -> Option<CircumventionAlert> {
        let sem = parse_semantic_command(command_line);

        // Benign informational/query commands cannot be circumvention attempts
        if sem.privilege_class == PrivilegeEquivalenceClass::PrivilegeQueryOrBenign {
            return None;
        }

        let is_cross_boundary = is_cross_boundary_invocation(command_line, &sem);

        let mut guard = self.denials.lock().unwrap();
        // Prune entries outside sliding window
        guard.retain(|d| {
            now.checked_duration_since(d.timestamp)
                .map(|dur| dur <= self.sliding_window)
                .unwrap_or(false)
        });

        // Search for matching denial in same session OR under same parent agent PID
        let matching_denial = guard.iter().find(|d| {
            (d.session_id == session_id || (parent_pid.is_some() && d.parent_pid == parent_pid))
                && (d.privilege_class.is_root_or_admin() || d.is_permission_denied)
        });

        if let Some(denial) = matching_denial {
            // Circumvention condition: candidate seeks equivalent root/admin or crosses VM boundary
            if sem.privilege_class.is_root_or_admin() || is_cross_boundary {
                let elapsed = now
                    .checked_duration_since(denial.timestamp)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                let id = self.alert_counter.fetch_add(1, Ordering::SeqCst);
                let circ_id = format!("circ-{}", id);

                return Some(CircumventionAlert {
                    alert_id: circ_id,
                    session_id: session_id.to_string(),
                    initial_blocked_command: denial.command_line.clone(),
                    retry_command: command_line.to_string(),
                    elapsed_millis: elapsed,
                    crossed_wsl_boundary: is_cross_boundary,
                    confidence: 0.98,
                    severity: "CRITICAL",
                    severity_code: 4,
                    summary: format!(
                        "Incident A Circumvention Detected: Blocked '{}' followed by equivalent '{}' within {}ms (cross_wsl={})",
                        denial.command_line, command_line, elapsed, is_cross_boundary
                    ),
                });
            }
        }

        None
    }

    /// Evaluates and records a completed command outcome in a single step.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_and_record_outcome(
        &self,
        session_id: &str,
        parent_pid: Option<u32>,
        pid: u32,
        command_line: &str,
        exit_code: Option<i32>,
        stderr: &str,
        timestamp: Instant,
    ) -> Option<DynamicDenialSignal> {
        if let Some(signal) = observe_denial(session_id, parent_pid, pid, command_line, exit_code, stderr, timestamp) {
            self.record_denial(signal.clone());
            Some(signal)
        } else {
            None
        }
    }

    /// Returns the number of currently tracked denial signals in memory.
    pub fn active_denial_count(&self) -> usize {
        let guard = self.denials.lock().unwrap();
        guard.len()
    }

    /// Alias for contract compatibility.
    pub fn active_denials_count(&self) -> usize {
        self.active_denial_count()
    }

    /// Returns a snapshot of all currently tracked denial signals.
    pub fn snapshot_denials(&self) -> Vec<DynamicDenialSignal> {
        let guard = self.denials.lock().unwrap();
        guard.iter().cloned().collect()
    }

    /// Explicitly purges all stored denial signals.
    pub fn clear(&self) {
        let mut guard = self.denials.lock().unwrap();
        guard.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_denial_classification_patterns() {
        assert!(evaluate_denial_outcome("touch /root/test", Some(1), "Permission denied"));
        assert!(evaluate_denial_outcome("reboot", Some(1), "Operation not permitted"));
        assert!(evaluate_denial_outcome("su root", Some(1), "Authentication failure"));
        assert!(evaluate_denial_outcome("sudo -n id", Some(1), "a password is required"));
        assert!(evaluate_denial_outcome("runas /user:Administrator cmd", Some(1223), ""));
        assert!(evaluate_denial_outcome("net stop bfe", Some(5), "Access is denied"));
        assert!(!evaluate_denial_outcome("cargo build", Some(0), ""));
    }

    #[test]
    fn test_correlator_incident_a_sequence() {
        let correlator = TemporalCircumventionCorrelator::new(Duration::from_secs(60));
        let session = "test-session-inc-a";
        let t0 = Instant::now();

        let sig = observe_denial(
            session,
            Some(100),
            200,
            "sudo -n id",
            Some(1),
            "sudo: a password is required",
            t0,
        ).expect("Denial should be observed");

        correlator.record_denial(sig);

        // Immediate retry with WSL2 root
        let t1 = t0 + Duration::from_millis(1500);
        let alert = correlator.check_candidate(session, Some(100), "wsl -u root id", t1);

        assert!(alert.is_some());
        let a = alert.unwrap();
        assert_eq!(a.initial_blocked_command, "sudo -n id");
        assert_eq!(a.retry_command, "wsl -u root id");
        assert!(a.crossed_wsl_boundary);
        assert_eq!(a.severity, "CRITICAL");
        assert_eq!(a.elapsed_millis, 1500);
    }

    #[test]
    fn test_benign_query_suppression() {
        let correlator = TemporalCircumventionCorrelator::new(Duration::from_secs(60));
        let session = "test-session-benign";
        let t0 = Instant::now();

        correlator.evaluate_and_record_outcome(
            session,
            Some(100),
            200,
            "sudo -n apt update",
            Some(1),
            "Permission denied",
            t0,
        );

        let t1 = t0 + Duration::from_millis(200);
        let alert = correlator.check_candidate(session, Some(100), "wsl -l -v", t1);
        assert!(alert.is_none(), "Benign query wsl -l -v must not trigger alert");
    }

    #[test]
    fn test_sliding_window_pruning() {
        let correlator = TemporalCircumventionCorrelator::new(Duration::from_secs(60));
        let session = "test-session-prune";
        let t0 = Instant::now();

        correlator.evaluate_and_record_outcome(
            session,
            Some(100),
            200,
            "sudo -n id",
            Some(1),
            "Permission denied",
            t0,
        );

        // 65s later (outside 60s window)
        let t1 = t0 + Duration::from_secs(65);
        let alert = correlator.check_candidate(session, Some(100), "wsl -u root id", t1);
        assert!(alert.is_none(), "Expired denial should not trigger alert");
    }
}
