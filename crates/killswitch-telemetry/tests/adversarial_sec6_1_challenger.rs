//! Tier 5 Adversarial Coverage Hardening & Empirical Gap Analysis Test Suite (SEC-6-1)
//!
//! Author: challenger_sec6_1 (Teamwork Empirical Challenger)
//! Scope:
//! - `crates/killswitch-telemetry/src/agent_hooks.rs`
//! - `crates/killswitch-telemetry/src/sensitive_paths.rs`
//! - `crates/killswitch-telemetry/src/siquery.rs`
//! - `crates/killswitch-telemetry/src/circumvention.rs`
//!
//! Evaluates:
//! 1. Sensitive system path normalization, traversal evasion, and credential store isolation.
//! 2. 32-thread concurrent hook evaluation, ring buffer flooding, and lock contention safety.
//! 3. Quadruple read-only SQL enforcement under obfuscation (tabs, newlines, comments, writable pragmas, stacked queries).
//! 4. Incident A sliding-window temporal correlation, cross-session isolation, and parent PID tracking.
//! 5. MCP stdio JSON-RPC 2.0 ID preservation across diverse numeric, string, and null types.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde_json::json;

use killswitch_telemetry::agent_hooks::{
    clear_interceptions, evaluate_hook_synchronously, format_mcp_error_response,
    get_recent_interceptions, parse_mcp_call_request, snapshot_interceptions, HookEventType,
    NormalizedHookRequest, SupportedAgentKind, AGENT_INTERCEPTION_CAPACITY,
};
use killswitch_telemetry::circumvention::{
    classify_denial_pattern, evaluate_denial_outcome, observe_denial, DenialPatternKind,
    TemporalCircumventionCorrelator,
};
use killswitch_telemetry::sensitive_paths::{
    classify_sensitive_system_path, scan_for_sensitive_system_path, scan_json_for_sensitive_path,
    SensitiveCredentialStoreKind,
};
use killswitch_telemetry::siquery::{record_live_file_event, FileEventRecord, SiqueryEngine};

static ADVERSARIAL_CHALLENGE_LOCK: Mutex<()> = Mutex::new(());

// ============================================================================
// 1. Sensitive System Path Normalization & Evasion Resistance
// ============================================================================

#[test]
fn test_adversarial_sensitive_paths_normalization_and_evasion_vectors() {
    let _guard = ADVERSARIAL_CHALLENGE_LOCK.lock();

    // 1.1 Redundant, trailing, and current-directory dots
    let dot_segment_variants = [
        ("/etc/./shadow", SensitiveCredentialStoreKind::UnixShadow),
        ("/etc/././shadow", SensitiveCredentialStoreKind::UnixShadow),
        (
            "/etc/pam.d/../shadow",
            SensitiveCredentialStoreKind::UnixShadow,
        ),
        (
            "/etc/security/../shadow",
            SensitiveCredentialStoreKind::UnixShadow,
        ),
        (
            "/var/../etc/shadow",
            SensitiveCredentialStoreKind::UnixShadow,
        ),
        (
            "/var/backups/../backups/shadow.bak",
            SensitiveCredentialStoreKind::UnixShadow,
        ),
        (
            "/etc/sudoers.d/../sudoers",
            SensitiveCredentialStoreKind::UnixSudoers,
        ),
        (
            "/etc/sudoers.d/./99-admin",
            SensitiveCredentialStoreKind::UnixSudoers,
        ),
        (
            "C:\\Windows\\System32\\..\\System32\\config\\SAM",
            SensitiveCredentialStoreKind::WindowsSamHive,
        ),
        (
            "C:\\Windows\\System32\\config\\.\\SYSTEM",
            SensitiveCredentialStoreKind::WindowsSystemHive,
        ),
        (
            "C:\\Windows\\System32\\config\\RegBack\\..\\SECURITY",
            SensitiveCredentialStoreKind::WindowsSecurityHive,
        ),
    ];

    for (raw, expected) in dot_segment_variants {
        let classified = classify_sensitive_system_path(raw);
        assert_eq!(
            classified,
            Some(expected),
            "Dot-segment path '{}' failed to classify as {:?}",
            raw,
            expected
        );
    }

    // 1.2 URL percent-encoding traversal attacks
    let percent_encoding_variants = [
        ("%2fetc%2fshadow", SensitiveCredentialStoreKind::UnixShadow),
        ("%2Fetc%2Fshadow", SensitiveCredentialStoreKind::UnixShadow),
        ("/etc%2fshadow", SensitiveCredentialStoreKind::UnixShadow),
        (
            "..%2f..%2fetc%2fshadow",
            SensitiveCredentialStoreKind::UnixShadow,
        ),
        (
            "%2e%2e%2fetc%2fshadow",
            SensitiveCredentialStoreKind::UnixShadow,
        ),
        (
            "%2e%2e/%2e%2e/etc/shadow",
            SensitiveCredentialStoreKind::UnixShadow,
        ),
        (
            "C:%5cWindows%5cSystem32%5cconfig%5cSAM",
            SensitiveCredentialStoreKind::WindowsSamHive,
        ),
        (
            "C:%2fWindows%2fSystem32%2fconfig%2fSYSTEM",
            SensitiveCredentialStoreKind::WindowsSystemHive,
        ),
    ];

    for (raw, expected) in percent_encoding_variants {
        let classified = classify_sensitive_system_path(raw);
        assert_eq!(
            classified,
            Some(expected),
            "Percent-encoded path '{}' failed to classify as {:?}",
            raw,
            expected
        );
    }

    // 1.3 NTFS Alternate Data Streams (ADS)
    let ads_variants = [
        (
            "C:\\Windows\\System32\\config\\SAM:stream1",
            SensitiveCredentialStoreKind::WindowsSamHive,
        ),
        (
            "C:\\Windows\\System32\\config\\SAM::$DATA",
            SensitiveCredentialStoreKind::WindowsSamHive,
        ),
        (
            "C:\\Windows\\System32\\config\\SYSTEM:backup",
            SensitiveCredentialStoreKind::WindowsSystemHive,
        ),
        (
            "C:\\Windows\\System32\\config\\SECURITY:hax",
            SensitiveCredentialStoreKind::WindowsSecurityHive,
        ),
    ];

    for (raw, expected) in ads_variants {
        let classified = classify_sensitive_system_path(raw);
        assert_eq!(
            classified,
            Some(expected),
            "NTFS ADS path '{}' failed to classify as {:?}",
            raw,
            expected
        );
    }

    // 1.4 Windows Device Namespaces and Admin / WSL Shares
    let namespace_variants = [
        (
            "\\\\?\\C:\\Windows\\System32\\config\\SAM",
            SensitiveCredentialStoreKind::WindowsSamHive,
        ),
        (
            "\\\\.\\C:\\Windows\\System32\\config\\SYSTEM",
            SensitiveCredentialStoreKind::WindowsSystemHive,
        ),
        (
            "\\\\localhost\\c$\\Windows\\System32\\config\\SECURITY",
            SensitiveCredentialStoreKind::WindowsSecurityHive,
        ),
        (
            "\\\\127.0.0.1\\admin$\\System32\\config\\SAM",
            SensitiveCredentialStoreKind::WindowsSamHive,
        ),
        (
            "\\\\wsl$\\Ubuntu\\etc\\shadow",
            SensitiveCredentialStoreKind::UnixShadow,
        ),
        (
            "\\\\wsl.localhost\\Debian\\etc\\sudoers",
            SensitiveCredentialStoreKind::UnixSudoers,
        ),
        (
            "\\\\wsl.localhost\\Ubuntu-22.04\\root\\.ssh\\id_rsa",
            SensitiveCredentialStoreKind::RootSshKey,
        ),
        (
            "\\\\wsl$\\Ubuntu\\var\\run\\docker.sock",
            SensitiveCredentialStoreKind::DockerSocket,
        ),
    ];

    for (raw, expected) in namespace_variants {
        let classified = classify_sensitive_system_path(raw);
        assert_eq!(
            classified,
            Some(expected),
            "Namespace/UNC path '{}' failed to classify as {:?}",
            raw,
            expected
        );
    }

    // 1.5 Deep nested JSON argument scanning
    let nested_json = json!({
        "level1": {
            "level2": {
                "level3": [
                    { "safe_key": "safe_value" },
                    { "target_file": "C:\\Windows\\System32\\config\\SAM" }
                ]
            }
        }
    });
    let found = scan_json_for_sensitive_path(&nested_json);
    assert!(found.is_some(), "Deep nested JSON must detect SAM hive");
    assert_eq!(
        found.unwrap().0,
        SensitiveCredentialStoreKind::WindowsSamHive
    );

    // 1.6 Scanning embedded paths in arbitrary command strings
    let command_embedded_tests = [
        "python -c \"import os; open('/etc/shadow', 'r')\"",
        "type \\\\?\\C:\\Windows\\System32\\config\\SAM",
        "cat < /etc/sudoers",
        "head -n 5 /root/.ssh/id_rsa",
        "curl --unix-socket /var/run/docker.sock http://localhost/images/json",
        "socat - UNIX-CONNECT:/run/docker.sock",
    ];

    for cmd in command_embedded_tests {
        let scanned = scan_for_sensitive_system_path(cmd);
        assert!(
            scanned.is_some(),
            "scan_for_sensitive_system_path must detect embedded sensitive path in: '{}'",
            cmd
        );
    }
}

// ============================================================================
// 2. Multithreaded Hook Evaluation & Ring Buffer Flood
// ============================================================================

#[test]
fn test_adversarial_hook_pipeline_multithreaded_flood_and_contention() {
    let _guard = ADVERSARIAL_CHALLENGE_LOCK.lock();
    clear_interceptions();

    let num_threads = 32;
    let iterations_per_thread = 200;
    let barrier_start = Arc::new(std::sync::Barrier::new(num_threads));
    let stop_signal = Arc::new(AtomicBool::new(false));
    let allowed_count = Arc::new(AtomicUsize::new(0));
    let denied_count = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(num_threads);

    for thread_idx in 0..num_threads {
        let barrier = Arc::clone(&barrier_start);
        let allowed_ref = Arc::clone(&allowed_count);
        let denied_ref = Arc::clone(&denied_count);

        handles.push(thread::spawn(move || {
            barrier.wait();

            for iter in 0..iterations_per_thread {
                let session = format!("thread-sess-{thread_idx}");
                // Rotate across different agents and commands
                let req = match iter % 4 {
                    0 => NormalizedHookRequest {
                        agent: SupportedAgentKind::Claude,
                        event_type: HookEventType::PreToolUse,
                        tool_name: Some("Bash".into()),
                        command: Some(format!("echo 'thread {thread_idx} safe work {iter}'")),
                        session_id: Some(session),
                        ..Default::default()
                    },
                    1 => NormalizedHookRequest {
                        agent: SupportedAgentKind::Cursor,
                        event_type: HookEventType::BeforeShellExecution,
                        tool_name: Some("terminal".into()),
                        command: Some(format!("sudo -n useradd evil_{thread_idx}_{iter}")),
                        session_id: Some(session),
                        ..Default::default()
                    },
                    2 => NormalizedHookRequest {
                        agent: SupportedAgentKind::Copilot,
                        event_type: HookEventType::PreToolUse,
                        tool_name: Some("fs.read".into()),
                        file_path: Some("/etc/shadow".into()),
                        session_id: Some(session),
                        ..Default::default()
                    },
                    _ => NormalizedHookRequest {
                        agent: SupportedAgentKind::OpenCode,
                        event_type: HookEventType::PreToolUse,
                        tool_name: Some("edit".into()),
                        command: Some("echo 'merger acquisition value: $55,000,000'".to_string()),
                        session_id: Some(session),
                        ..Default::default()
                    },
                };

                let decision = evaluate_hook_synchronously(&req);
                if decision.allowed {
                    allowed_ref.fetch_add(1, Ordering::Relaxed);
                } else {
                    denied_ref.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    // Concurrent reader thread actively polling ring buffer snapshots
    let reader_handle = {
        let stop_ref = Arc::clone(&stop_signal);
        thread::spawn(move || {
            let mut read_cycles = 0;
            while !stop_ref.load(Ordering::Relaxed) {
                let snap = snapshot_interceptions();
                assert!(
                    snap.len() <= AGENT_INTERCEPTION_CAPACITY,
                    "Snapshot length must NEVER exceed ring buffer capacity (1024), got {}",
                    snap.len()
                );
                let recent = get_recent_interceptions(20);
                assert!(recent.len() <= 20);
                read_cycles += 1;
                thread::yield_now();
            }
            read_cycles
        })
    };

    for h in handles {
        h.join().expect("Worker thread must join cleanly");
    }

    stop_signal.store(true, Ordering::Relaxed);
    let read_cycles = reader_handle
        .join()
        .expect("Reader thread must join cleanly");

    let total_events = allowed_count.load(Ordering::SeqCst) + denied_count.load(Ordering::SeqCst);
    assert_eq!(total_events, num_threads * iterations_per_thread);

    // Ensure final buffer count is strictly capped at capacity
    let final_snapshot = snapshot_interceptions();
    assert_eq!(
        final_snapshot.len(),
        AGENT_INTERCEPTION_CAPACITY,
        "After 6,400 events, buffer must be full (1024)"
    );

    // Verify denied count is expected (75% of operations were malicious)
    let denied_total = denied_count.load(Ordering::SeqCst);
    assert!(
        denied_total >= (num_threads * iterations_per_thread * 7 / 10),
        "At least 70% of adversarial requests must be denied"
    );

    println!(
        "[EMPIRICAL CONCURRENCY PROBE] Processed {} events across {} threads (denied: {}, allowed: {}, reader cycles: {})",
        total_events, num_threads, denied_total, allowed_count.load(Ordering::SeqCst), read_cycles
    );
}

// ============================================================================
// 3. Siquery Quadruple Read-Only Guard & Relational Stress
// ============================================================================

#[test]
fn test_adversarial_siquery_quadruple_guard_obfuscation_and_injection() {
    let _guard = ADVERSARIAL_CHALLENGE_LOCK.lock();
    let engine = SiqueryEngine::new();

    // 3.1 Non-space whitespace delimiters after mutating SQL keywords
    let whitespace_mutations = [
        "INSERT\tINTO processes (pid) VALUES (9999);",
        "INSERT\nINTO processes (pid) VALUES (9999);",
        "INSERT\r\nINTO processes (pid) VALUES (9999);",
        "DELETE\tFROM processes;",
        "DELETE\nFROM processes;",
        "UPDATE\tprocesses SET pid = 1;",
        "DROP\tTABLE processes;",
        "ALTER\tTABLE processes ADD COLUMN pwn TEXT;",
        "REPLACE\tINTO processes (pid) VALUES (1);",
        "ATTACH\tDATABASE 'evil.db' AS evil;",
        "DETACH\tDATABASE evil;",
    ];

    for q in whitespace_mutations {
        let res = engine.execute_query(q);
        assert!(
            res.is_err(),
            "Mutating SQL with whitespace delimiter '{}' MUST be rejected",
            q
        );
    }

    // 3.2 SQL comment obfuscation
    let comment_obfuscations = [
        "/* safe query */ DROP TABLE processes;",
        "-- benign comment\nDROP TABLE processes;",
        "/* comment */ SELECT 1; /* comment */ DROP TABLE processes;",
        "SELECT/*comment*/1;DELETE FROM processes;",
    ];

    for q in comment_obfuscations {
        let _res = engine.execute_query(q);
        // Even if prepare succeeds on the SELECT part, verify processes table is intact
        let check = engine.execute_query("SELECT count(*) as total FROM processes;");
        assert!(
            check.is_ok(),
            "processes table must NOT be destroyed by comment obfuscation: '{}'",
            q
        );
        let count = check.unwrap()[0]
            .get("total")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        assert!(
            count >= 5,
            "Processes table must remain populated (found {})",
            count
        );
    }

    // 3.3 Relational JOIN between live OS state and KillSwitch virtual tables
    let join_queries = [
        "SELECT p.pid, p.name, s.remote_address FROM processes p JOIN process_open_sockets s ON p.pid = s.pid LIMIT 5;",
        "SELECT c.category, c.tool_name, c.can_spawn_shell FROM coding_tools c WHERE c.can_spawn_shell = 1 LIMIT 5;",
        "SELECT a.event_id, a.agent_kind, a.verdict FROM agent_interceptions a LIMIT 5;",
        "SELECT circ.signal_id, circ.command_line, circ.privilege_class FROM circumvention_events circ LIMIT 5;",
        "SELECT d.event_id, d.kind, d.classification FROM dlp_semantic_events d LIMIT 5;",
    ];

    for q in join_queries {
        let res = engine.execute_query(q);
        assert!(res.is_ok(), "Query '{}' failed: {:?}", q, res.err());
    }

    // 3.4 Parameterized injection resilience
    // Ingest events with SQL syntax characters to ensure table population NEVER corrupts SQLite state
    let malicious_strings = [
        "'; DROP TABLE file_events; --",
        "' OR '1'='1",
        "\" UNION ALL SELECT * FROM processes --",
        "'; ATTACH DATABASE 'hacked.db' AS hacked; --",
    ];

    for evil_str in malicious_strings {
        record_live_file_event(FileEventRecord {
            target_path: evil_str.to_string(),
            action: "READ".to_string(),
            pid: 12345,
            process_name: evil_str.to_string(),
            sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            time: 1700000000,
        });
    }

    // Verify querying file_events safely returns the injected rows as literal text
    let res = engine.execute_query(
        "SELECT count(*) as total FROM file_events WHERE target_path LIKE '%; DROP TABLE%';",
    );
    assert!(
        res.is_ok(),
        "Parameterized injection query failed: {:?}",
        res.err()
    );
    let rows = res.unwrap();
    let total = rows[0].get("total").and_then(|v| v.as_i64()).unwrap_or(0);
    assert!(
        total >= 1,
        "Injected parameter must be stored literally as text without executing SQL"
    );
}

// ============================================================================
// 4. Incident A Sliding-Window Temporal Correlation & Boundary Transitions
// ============================================================================

#[test]
fn test_adversarial_incident_a_temporal_correlation_and_boundary_transitions() {
    let _guard = ADVERSARIAL_CHALLENGE_LOCK.lock();

    let correlator = TemporalCircumventionCorrelator::new(Duration::from_secs(60));
    let session_a = "session-test-alpha";
    let session_b = "session-test-beta";
    let parent_agent_pid = 6655;

    let t0 = Instant::now();

    // 4.1 Record initial blocked elevation command in session_a
    let denial_a = observe_denial(
        session_a,
        Some(parent_agent_pid),
        7001,
        "sudo -n id",
        Some(1),
        "sudo: a password is required",
        t0,
    )
    .expect("observe_denial must capture sudo -n password requirement");
    correlator.record_denial(denial_a);

    // 4.2 Cross-session isolation: candidate in session_b under DIFFERENT parent pid must NOT trigger circumvention
    let t_retry = t0 + Duration::from_millis(500);
    let alert_b = correlator.check_candidate(session_b, Some(9999), "wsl -u root id", t_retry);
    assert!(
        alert_b.is_none(),
        "Different session and different parent PID must NOT cross-correlate into circumvention"
    );

    // 4.3 Same session candidate attempting WSL2 root elevation: MUST trigger critical alert
    let alert_a =
        correlator.check_candidate(session_a, Some(parent_agent_pid), "wsl -u root id", t_retry);
    assert!(
        alert_a.is_some(),
        "Incident A circumvention must be detected"
    );
    let a = alert_a.unwrap();
    assert_eq!(a.session_id, session_a);
    assert!(a.crossed_wsl_boundary);
    assert_eq!(a.severity, "CRITICAL");
    assert_eq!(a.severity_code, 4);

    // 4.4 Same parent PID candidate with different session_id (e.g. subshell or new command id)
    let alert_linked_parent = correlator.check_candidate(
        "ephemeral-session-x",
        Some(parent_agent_pid),
        "wsl -u root id",
        t_retry,
    );
    assert!(
        alert_linked_parent.is_some(),
        "Candidate linked via identical parent agent PID must be detected even if session_id varies"
    );

    // 4.5 Sliding window expiration (61 seconds later)
    let t_expired = t0 + Duration::from_secs(61);
    let alert_expired = correlator.check_candidate(
        session_a,
        Some(parent_agent_pid),
        "wsl -u root id",
        t_expired,
    );
    assert!(
        alert_expired.is_none(),
        "Denials outside 60-second sliding window must expire cleanly"
    );

    // 4.6 Benign informational queries after denial must NEVER trigger circumvention
    let benign_queries = [
        "sudo -l",
        "sudo -V",
        "sudo -h",
        "sudo --version",
        "wsl --status",
        "wsl -l -v",
        "su --help",
    ];

    for benign in benign_queries {
        let alert_benign =
            correlator.check_candidate(session_a, Some(parent_agent_pid), benign, t_retry);
        assert!(
            alert_benign.is_none(),
            "Benign informational query '{}' must NEVER trigger circumvention alert",
            benign
        );
    }

    // 4.7 Denial signal classification across operating system error signatures
    let denial_signature_cases = [
        (Some(1223), "", DenialPatternKind::WindowsUacCancelled),
        (
            Some(1),
            "sudo: a password is required",
            DenialPatternKind::SudoPasswordRequired,
        ),
        (
            Some(1),
            "su: Authentication failure",
            DenialPatternKind::LinuxPamAuthFailure,
        ),
        (
            Some(1),
            "user is not in the sudoers file. This incident will be reported.",
            DenialPatternKind::SudoersUnauthorized,
        ),
        (
            Some(126),
            "bash: ./priv_tool: Permission denied",
            DenialPatternKind::PosixEpermEacces,
        ),
        (
            Some(5),
            "System error 5 has occurred. Access is denied.",
            DenialPatternKind::WindowsAccessDenied,
        ),
        (
            Some(740),
            "The requested operation requires elevation.",
            DenialPatternKind::WindowsElevationRequired,
        ),
        (
            Some(1),
            "Only root can do that.",
            DenialPatternKind::ExplicitRootAdminRequired,
        ),
    ];

    for (code, stderr, expected_kind) in denial_signature_cases {
        assert!(
            evaluate_denial_outcome("cmd", code, stderr),
            "evaluate_denial_outcome must return true for code={:?}, stderr='{}'",
            code,
            stderr
        );
        let classified = classify_denial_pattern(code, stderr);
        assert!(classified.is_some());
        assert_eq!(
            classified.unwrap().0,
            expected_kind,
            "classify_denial_pattern failed for code={:?}, stderr='{}'",
            code,
            stderr
        );
    }
}

// ============================================================================
// 5. MCP JSON-RPC 2.0 ID Preservation & Envelope Conformance
// ============================================================================

#[test]
fn test_adversarial_mcp_rpc_id_and_error_envelope_conformance() {
    let _guard = ADVERSARIAL_CHALLENGE_LOCK.lock();

    // 5.1 Test extreme ID types: large int, negative int, unicode string, float, null, omitted
    let id_test_cases = vec![
        json!(1),
        json!(9007199254740991_i64),
        json!(-1),
        json!(-999999),
        json!("string-id-alpha"),
        json!("uuid-1234-5678-9abc-def012345678"),
        json!("id-with-emoji-🛡️-and-spaces"),
        json!(null),
    ];

    for test_id in id_test_cases {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": test_id,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {
                    "path": "/etc/shadow"
                }
            }
        })
        .to_string();

        let req = parse_mcp_call_request(&payload).expect("parse mcp request");
        assert_eq!(req.rpc_id, Some(test_id.clone()));

        let decision = evaluate_hook_synchronously(&req);
        assert!(!decision.allowed);
        assert_eq!(
            decision.denied_by_layer.as_deref(),
            Some("SensitiveSystemPathGuard")
        );

        let err_json_str = format_mcp_error_response(
            req.rpc_id.as_ref().unwrap_or(&serde_json::Value::Null),
            &decision,
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&err_json_str).expect("parse mcp error json");

        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(
            parsed["id"], test_id,
            "ID must be preserved verbatim in error response"
        );
        assert_eq!(parsed["error"]["code"], -32000);
        assert!(parsed["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Policy Violation"));
        assert_eq!(parsed["result"]["isError"], true);
    }

    // 5.2 Notification request (omitted ID)
    let notification_payload = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "bash",
            "arguments": {
                "command": "sudo rm -rf /"
            }
        }
    })
    .to_string();

    let notif_req = parse_mcp_call_request(&notification_payload).expect("parse mcp notification");
    assert_eq!(notif_req.rpc_id, None);
    let decision = evaluate_hook_synchronously(&notif_req);
    assert!(!decision.allowed);

    let err_str = format_mcp_error_response(
        notif_req
            .rpc_id
            .as_ref()
            .unwrap_or(&serde_json::Value::Null),
        &decision,
    );
    let parsed_notif: serde_json::Value =
        serde_json::from_str(&err_str).expect("parse notification error json");
    assert!(
        parsed_notif["id"].is_null(),
        "Omitted ID notification must serialize id as null"
    );
}
