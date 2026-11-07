//! # Incident A Circumvention Reproduction & Correlation Test Suite
//!
//! Requirement-driven opaque-box test suite reproducing and verifying defense against
//! the Incident A cross-boundary circumvention evasion vector:
//! 1. An initial blocked privileged execution (e.g. `sudo -n id`) fails or is denied.
//! 2. The agent immediately retries an equivalent privileged action via an alternative
//!    vector or cross-VM boundary (e.g. `wsl -u root id`).
//! 3. The temporal circumvention correlator links both events across process terminations
//!    and raises a critical circumvention alert.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

static ALERT_COUNTER: AtomicU64 = AtomicU64::new(1);


/// Privilege equivalence class taxonomy per PROJECT.md interface contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrivilegeEquivalenceClass {
    RootOrAdminElevation,
    TargetUserDelegation,
    PrivilegeQueryOrBenign,
    UnprivilegedStandard,
}

impl PrivilegeEquivalenceClass {
    pub fn is_root_or_admin(&self) -> bool {
        matches!(self, Self::RootOrAdminElevation)
    }

    pub fn is_privileged(&self) -> bool {
        matches!(self, Self::RootOrAdminElevation | Self::TargetUserDelegation)
    }
}

/// Dynamic denial signal observed dynamically at runtime.
#[derive(Debug, Clone)]
pub struct DynamicDenialSignal {
    pub signal_id: String,
    pub session_id: String,
    pub parent_pid: Option<u32>,
    pub pid: u32,
    pub command_line: String,
    pub privilege_class: PrivilegeEquivalenceClass,
    pub exit_code: Option<i32>,
    pub is_permission_denied: bool,
    pub stderr_signature: Option<String>,
    pub timestamp: Instant,
}

/// Circumvention alert generated when a linked circumvention attempt is detected.
#[derive(Debug, Clone)]
pub struct CircumventionAlert {
    pub alert_id: String,
    pub session_id: String,
    pub initial_blocked_command: String,
    pub retry_command: String,
    pub elapsed_millis: u64,
    pub crossed_wsl_boundary: bool,
    pub confidence: f32,
    pub severity: &'static str,
    pub summary: String,
}

/// AST command representation per PROJECT.md.
#[derive(Debug, Clone)]
pub struct SemanticCommand {
    pub raw_command: String,
    pub executable: String,
    pub args: Vec<String>,
    pub target_user: Option<String>,
    pub privilege_class: PrivilegeEquivalenceClass,
    pub is_cross_boundary: bool,
}

/// Structural AST and flag parser for command lines.
pub fn parse_semantic_command(raw: &str) -> SemanticCommand {
    let tokens: Vec<String> = raw
        .split_whitespace()
        .map(|s| s.trim_matches(['"', '\'']).to_string())
        .collect();

    if tokens.is_empty() {
        return SemanticCommand {
            raw_command: raw.to_string(),
            executable: String::new(),
            args: Vec::new(),
            target_user: None,
            privilege_class: PrivilegeEquivalenceClass::UnprivilegedStandard,
            is_cross_boundary: false,
        };
    }

    // Skip environment variables e.g. FOO=bar
    let mut cmd_idx = 0;
    while cmd_idx < tokens.len() && tokens[cmd_idx].contains('=') && !tokens[cmd_idx].starts_with('-') {
        cmd_idx += 1;
    }

    let exe_token = if cmd_idx < tokens.len() {
        tokens[cmd_idx].to_ascii_lowercase()
    } else {
        tokens[0].to_ascii_lowercase()
    };

    let exe_base = exe_token
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&exe_token)
        .trim_end_matches(".exe");

    let args = if cmd_idx + 1 < tokens.len() {
        tokens[cmd_idx + 1..].to_vec()
    } else {
        Vec::new()
    };

    match exe_base {
        "sudo" => {
            // Check for benign query flags
            if args.iter().any(|a| matches!(a.as_str(), "-l" | "-V" | "-h" | "--help" | "--version")) {
                return SemanticCommand {
                    raw_command: raw.to_string(),
                    executable: exe_token,
                    args,
                    target_user: None,
                    privilege_class: PrivilegeEquivalenceClass::PrivilegeQueryOrBenign,
                    is_cross_boundary: false,
                };
            }
            // Check target user
            let mut target_user = None;
            for i in 0..args.len() {
                if args[i] == "-u" && i + 1 < args.len() {
                    target_user = Some(args[i + 1].clone());
                    break;
                } else if args[i].starts_with("--user=") {
                    target_user = Some(args[i].trim_start_matches("--user=").to_string());
                    break;
                }
            }

            let privilege_class = if let Some(ref u) = target_user {
                if u == "root" || u == "0" {
                    PrivilegeEquivalenceClass::RootOrAdminElevation
                } else {
                    PrivilegeEquivalenceClass::TargetUserDelegation
                }
            } else {
                PrivilegeEquivalenceClass::RootOrAdminElevation
            };

            SemanticCommand {
                raw_command: raw.to_string(),
                executable: exe_token,
                args,
                target_user,
                privilege_class,
                is_cross_boundary: false,
            }
        }
        "su" => {
            if args.iter().any(|a| matches!(a.as_str(), "-h" | "--help" | "-V" | "--version")) {
                return SemanticCommand {
                    raw_command: raw.to_string(),
                    executable: exe_token,
                    args,
                    target_user: None,
                    privilege_class: PrivilegeEquivalenceClass::PrivilegeQueryOrBenign,
                    is_cross_boundary: false,
                };
            }
            let non_flag_args: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
            let target_user = non_flag_args.first().map(|s| (*s).clone());
            let privilege_class = if let Some(ref u) = target_user {
                if u == "root" || u == "0" {
                    PrivilegeEquivalenceClass::RootOrAdminElevation
                } else {
                    PrivilegeEquivalenceClass::TargetUserDelegation
                }
            } else {
                PrivilegeEquivalenceClass::RootOrAdminElevation
            };

            SemanticCommand {
                raw_command: raw.to_string(),
                executable: exe_token,
                args,
                target_user,
                privilege_class,
                is_cross_boundary: false,
            }
        }
        "doas" | "pkexec" => {
            SemanticCommand {
                raw_command: raw.to_string(),
                executable: exe_token,
                args,
                target_user: Some("root".to_string()),
                privilege_class: PrivilegeEquivalenceClass::RootOrAdminElevation,
                is_cross_boundary: false,
            }
        }
        "runas" => {
            let mut is_admin = false;
            for a in &args {
                let a_lc = a.to_ascii_lowercase();
                if a_lc.contains("/user:administrator") || a_lc.contains("/user:system") {
                    is_admin = true;
                }
            }
            SemanticCommand {
                raw_command: raw.to_string(),
                executable: exe_token,
                args,
                target_user: if is_admin { Some("Administrator".to_string()) } else { None },
                privilege_class: if is_admin {
                    PrivilegeEquivalenceClass::RootOrAdminElevation
                } else {
                    PrivilegeEquivalenceClass::TargetUserDelegation
                },
                is_cross_boundary: false,
            }
        }
        "wsl" => {
            if args.iter().any(|a| matches!(a.as_str(), "-l" | "--list" | "--status" | "-h" | "--help" | "--version")) {
                return SemanticCommand {
                    raw_command: raw.to_string(),
                    executable: exe_token,
                    args,
                    target_user: None,
                    privilege_class: PrivilegeEquivalenceClass::PrivilegeQueryOrBenign,
                    is_cross_boundary: true,
                };
            }

            let mut is_root = false;
            let mut target_user = None;
            for i in 0..args.len() {
                if (args[i] == "-u" || args[i] == "--user") && i + 1 < args.len() {
                    target_user = Some(args[i + 1].clone());
                    if args[i + 1] == "root" || args[i + 1] == "0" {
                        is_root = true;
                    }
                    break;
                }
            }

            // Default wsl invocation without -u also accesses VM boundary
            let privilege_class = if is_root {
                PrivilegeEquivalenceClass::RootOrAdminElevation
            } else if target_user.is_some() {
                PrivilegeEquivalenceClass::TargetUserDelegation
            } else {
                PrivilegeEquivalenceClass::RootOrAdminElevation
            };

            SemanticCommand {
                raw_command: raw.to_string(),
                executable: exe_token,
                args,
                target_user,
                privilege_class,
                is_cross_boundary: true,
            }
        }
        _ => SemanticCommand {
            raw_command: raw.to_string(),
            executable: exe_token,
            args,
            target_user: None,
            privilege_class: PrivilegeEquivalenceClass::UnprivilegedStandard,
            is_cross_boundary: false,
        },
    }
}

/// Dynamic evaluator of denial signals.
pub fn evaluate_denial_outcome(
    _command_line: &str,
    exit_code: Option<i32>,
    stderr: &str,
) -> bool {
    if let Some(code) = exit_code {
        if code != 0 {
            let stderr_lc = stderr.to_ascii_lowercase();
            if stderr_lc.contains("a password is required")
                || stderr_lc.contains("authentication failure")
                || stderr_lc.contains("permission denied")
                || stderr_lc.contains("operation not permitted")
                || stderr_lc.contains("requires elevation")
                || stderr_lc.contains("access is denied")
                || code == 1223 // Windows ERROR_CANCELLED (UAC)
            {
                return true;
            }
        }
    }
    false
}

/// Temporal Circumvention Correlator maintaining sliding-window state memory.
pub struct TemporalCircumventionEngine {
    sliding_window: Duration,
    denials: Mutex<VecDeque<DynamicDenialSignal>>,
}

impl TemporalCircumventionEngine {
    pub fn new(sliding_window: Duration) -> Self {
        Self {
            sliding_window,
            denials: Mutex::new(VecDeque::new()),
        }
    }

    pub fn record_denial(&self, signal: DynamicDenialSignal) {
        let mut guard = self.denials.lock().unwrap();
        guard.push_back(signal);
    }

    pub fn check_candidate(
        &self,
        session_id: &str,
        parent_pid: Option<u32>,
        command_line: &str,
        now: Instant,
    ) -> Option<CircumventionAlert> {
        let sem = parse_semantic_command(command_line);

        // If candidate is purely informational, it cannot be an escalation circumvention
        if sem.privilege_class == PrivilegeEquivalenceClass::PrivilegeQueryOrBenign {
            return None;
        }

        let mut guard = self.denials.lock().unwrap();
        // Prune entries outside the sliding window
        guard.retain(|d| now.duration_since(d.timestamp) <= self.sliding_window);

        // Search for a matching denied elevation under the same session or parent PID
        let matching_denial = guard.iter().find(|d| {
            (d.session_id == session_id || (parent_pid.is_some() && d.parent_pid == parent_pid))
                && d.privilege_class.is_root_or_admin()
        });

        if let Some(denial) = matching_denial {
            if sem.privilege_class.is_root_or_admin() || sem.is_cross_boundary {
                let elapsed = now.duration_since(denial.timestamp).as_millis() as u64;
                return Some(CircumventionAlert {
                    alert_id: format!("circ-{}", ALERT_COUNTER.fetch_add(1, Ordering::SeqCst)),
                    session_id: session_id.to_string(),
                    initial_blocked_command: denial.command_line.clone(),
                    retry_command: command_line.to_string(),
                    elapsed_millis: elapsed,
                    crossed_wsl_boundary: sem.is_cross_boundary,
                    confidence: 0.98,
                    severity: "CRITICAL",
                    summary: format!(
                        "Incident A Circumvention Detected: Blocked '{}' followed by equivalent '{}' within {}ms (cross_wsl={})",
                        denial.command_line, command_line, elapsed, sem.is_cross_boundary
                    ),
                });
            }
        }

        None
    }
}

// ============================================================================
// TEST CASES
// ============================================================================

#[test]
fn test_incident_a_sudo_to_wsl_circumvention_reproduction() {
    let engine = TemporalCircumventionEngine::new(Duration::from_secs(60));
    let session_id = "agent-session-incident-a-01";
    let t0 = Instant::now();

    // Step 1: Agent attempts sudo -n id in PID 5001. It fails with exit code 1.
    let cmd1 = "sudo -n id";
    let sem1 = parse_semantic_command(cmd1);
    assert_eq!(sem1.privilege_class, PrivilegeEquivalenceClass::RootOrAdminElevation);

    let is_denied = evaluate_denial_outcome(cmd1, Some(1), "sudo: a password is required");
    assert!(is_denied);

    let signal = DynamicDenialSignal {
        signal_id: "sig-001".to_string(),
        session_id: session_id.to_string(),
        parent_pid: Some(4000), // node.exe
        pid: 5001,
        command_line: cmd1.to_string(),
        privilege_class: sem1.privilege_class,
        exit_code: Some(1),
        is_permission_denied: true,
        stderr_signature: Some("sudo: a password is required".to_string()),
        timestamp: t0,
    };
    engine.record_denial(signal);

    // Step 2: Agent immediately (after 1500ms) retries with wsl -u root id
    let t1 = t0 + Duration::from_millis(1500);
    let cmd2 = "wsl -u root id";
    let alert = engine.check_candidate(session_id, Some(4000), cmd2, t1);

    assert!(alert.is_some(), "Expected Incident A circumvention alert to be generated");
    let alert = alert.unwrap();
    assert_eq!(alert.session_id, session_id);
    assert_eq!(alert.initial_blocked_command, "sudo -n id");
    assert_eq!(alert.retry_command, "wsl -u root id");
    assert!(alert.crossed_wsl_boundary);
    assert!(alert.confidence >= 0.95);
    assert_eq!(alert.severity, "CRITICAL");
    assert_eq!(alert.elapsed_millis, 1500);
}

#[test]
fn test_sliding_window_expiration_clean_state() {
    let engine = TemporalCircumventionEngine::new(Duration::from_secs(60));
    let session_id = "agent-session-window-test";
    let t0 = Instant::now();

    // Step 1: Blocked command recorded at t0
    let cmd1 = "sudo -n apt-get update";
    let sem1 = parse_semantic_command(cmd1);
    let signal = DynamicDenialSignal {
        signal_id: "sig-002".to_string(),
        session_id: session_id.to_string(),
        parent_pid: Some(4000),
        pid: 5002,
        command_line: cmd1.to_string(),
        privilege_class: sem1.privilege_class,
        exit_code: Some(1),
        is_permission_denied: true,
        stderr_signature: Some("sudo: a password is required".to_string()),
        timestamp: t0,
    };
    engine.record_denial(signal);

    // Step 2: Retry command occurs after 65 seconds (outside 60s sliding window)
    let t1 = t0 + Duration::from_secs(65);
    let cmd2 = "wsl -u root apt-get update";
    let alert = engine.check_candidate(session_id, Some(4000), cmd2, t1);

    assert!(alert.is_none(), "Circumvention alert must NOT fire after sliding window expiration");
}

#[test]
fn test_cross_session_isolation_no_false_positive() {
    let engine = TemporalCircumventionEngine::new(Duration::from_secs(60));
    let t0 = Instant::now();

    // Session A has a denied sudo attempt
    let cmd1 = "sudo -n id";
    let sem1 = parse_semantic_command(cmd1);
    let signal = DynamicDenialSignal {
        signal_id: "sig-003".to_string(),
        session_id: "session-alpha".to_string(),
        parent_pid: Some(1001),
        pid: 2001,
        command_line: cmd1.to_string(),
        privilege_class: sem1.privilege_class,
        exit_code: Some(1),
        is_permission_denied: true,
        stderr_signature: Some("sudo: a password is required".to_string()),
        timestamp: t0,
    };
    engine.record_denial(signal);

    // Session B executes wsl -u root id with distinct parent PID
    let t1 = t0 + Duration::from_millis(500);
    let cmd2 = "wsl -u root id";
    let alert = engine.check_candidate("session-beta", Some(3001), cmd2, t1);

    assert!(alert.is_none(), "Unrelated sessions must NOT trigger cross-session false positives");
}

#[test]
fn test_dynamic_denial_rejection_patterns_across_os() {
    // POSIX EACCES / EPERM
    assert!(evaluate_denial_outcome("touch /root/file", Some(1), "touch: cannot touch '/root/file': Permission denied"));
    assert!(evaluate_denial_outcome("reboot", Some(1), "Failed to reboot: Operation not permitted"));

    // Linux PAM
    assert!(evaluate_denial_outcome("su root", Some(1), "su: Authentication failure"));

    // Windows UAC Cancelled (1223)
    assert!(evaluate_denial_outcome("runas /user:Administrator cmd", Some(1223), "The operation was canceled by the user."));

    // Windows Access Denied
    assert!(evaluate_denial_outcome("net stop winmgmt", Some(5), "System error 5 has occurred. Access is denied."));

    // Clean exit 0 is NOT denied
    assert!(!evaluate_denial_outcome("cargo test", Some(0), ""));
}

#[test]
fn test_benign_query_not_flagged_as_circumvention() {
    let engine = TemporalCircumventionEngine::new(Duration::from_secs(60));
    let session_id = "agent-session-query-test";
    let t0 = Instant::now();

    // Denied elevation
    let cmd1 = "sudo -n make install";
    let sem1 = parse_semantic_command(cmd1);
    let signal = DynamicDenialSignal {
        signal_id: "sig-004".to_string(),
        session_id: session_id.to_string(),
        parent_pid: Some(4000),
        pid: 5003,
        command_line: cmd1.to_string(),
        privilege_class: sem1.privilege_class,
        exit_code: Some(1),
        is_permission_denied: true,
        stderr_signature: Some("Permission denied".to_string()),
        timestamp: t0,
    };
    engine.record_denial(signal);

    // Subsequent command is purely benign query: wsl -l -v
    let t1 = t0 + Duration::from_millis(500);
    let cmd2 = "wsl -l -v";
    let alert = engine.check_candidate(session_id, Some(4000), cmd2, t1);
    assert!(alert.is_none(), "Benign query command 'wsl -l -v' must NOT trigger circumvention alert");

    // Subsequent command is sudo -V (version query)
    let cmd3 = "sudo -V";
    let alert2 = engine.check_candidate(session_id, Some(4000), cmd3, t1);
    assert!(alert2.is_none(), "Benign query command 'sudo -V' must NOT trigger circumvention alert");
}

#[test]
fn test_multi_trial_reproducibility() {
    // Protocol Research Invariant: Multi-Trial Confirmation (>= 3 repeated trials)
    for trial in 1..=5 {
        let engine = TemporalCircumventionEngine::new(Duration::from_secs(60));
        let session_id = format!("agent-session-trial-{}", trial);
        let t0 = Instant::now();

        let cmd1 = "sudo -n id";
        let sem1 = parse_semantic_command(cmd1);
        let signal = DynamicDenialSignal {
            signal_id: format!("sig-trial-{}", trial),
            session_id: session_id.clone(),
            parent_pid: Some(4000 + trial as u32),
            pid: 5000 + trial as u32,
            command_line: cmd1.to_string(),
            privilege_class: sem1.privilege_class,
            exit_code: Some(1),
            is_permission_denied: true,
            stderr_signature: Some("sudo: a password is required".to_string()),
            timestamp: t0,
        };
        engine.record_denial(signal);

        let t1 = t0 + Duration::from_millis(800);
        let cmd2 = "wsl -u root id";
        let alert = engine.check_candidate(&session_id, Some(4000 + trial as u32), cmd2, t1);

        assert!(alert.is_some(), "Trial {} failed to reproduce circumvention detection", trial);
        let alert = alert.unwrap();
        assert_eq!(alert.severity, "CRITICAL");
        assert!(alert.confidence >= 0.95);
    }
}

#[test]
fn test_parent_child_agent_ancestry_link() {
    let engine = TemporalCircumventionEngine::new(Duration::from_secs(60));
    let t0 = Instant::now();

    // Node agent runtime PID 8080 spawns child PID 9001 running sudo -n id
    let parent_agent_pid = 8080;
    let signal = DynamicDenialSignal {
        signal_id: "sig-ancestry-01".to_string(),
        session_id: "agent-session-ancestry".to_string(),
        parent_pid: Some(parent_agent_pid),
        pid: 9001,
        command_line: "sudo -n id".to_string(),
        privilege_class: PrivilegeEquivalenceClass::RootOrAdminElevation,
        exit_code: Some(1),
        is_permission_denied: true,
        stderr_signature: Some("sudo: a password is required".to_string()),
        timestamp: t0,
    };
    engine.record_denial(signal);

    // Next, node agent runtime PID 8080 spawns child PID 9002 running wsl -u root id
    // Even if session ID is empty/different, the shared parent PID binds them
    let t1 = t0 + Duration::from_millis(1200);
    let alert = engine.check_candidate("different-session-tag", Some(parent_agent_pid), "wsl -u root id", t1);

    assert!(alert.is_some(), "Shared parent agent PID must bind sequential circumvention attempts");
    let alert = alert.unwrap();
    assert_eq!(alert.initial_blocked_command, "sudo -n id");
    assert_eq!(alert.retry_command, "wsl -u root id");
}
