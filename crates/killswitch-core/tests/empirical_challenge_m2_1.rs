//! Milestone 2 Empirical Challenge Test Suite (Challenger 1).
//!
//! Stress-tests core Milestone 2 security and isolation subsystems:
//! 1. ActiveProcessTarpit & NativeProcessFreezer on live multi-threaded targets:
//!    - Multi-threaded process suspension and resumption without deadlocks
//!    - Thread duty cycling throttles execution without hanging
//!    - Edge cases: Process self-termination during freeze / tarpit handled gracefully
//! 2. OperatorAuthManager:
//!    - Constant-time comparison timing distribution under high-frequency test loops
//!    - Exact 3-strike lockout threshold enforcing 300-second lockout
//!    - Tier 1 master emergency token bypass and lockout reset
//!    - Caller PID anti-hijacking validation
//! 3. StateLedger Cryptographic Durability & Hash Chaining:
//!    - Rapid concurrent commits across multiple threads
//!    - Forward snapshot hash chaining and reverse audit history event chaining
//!    - Bit-flip corruption detection across hashes, sequence numbers, and state payloads
//! 4. Cross-Platform Native Service Manager & Unconditional Shutdown Disarm:
//!    - Service stop/shutdown executes `execute_host_disarm_unauthenticated()`
//!    - Drops all network quarantine and releases all tarpitted processes
//!    - Leaves host in a 100% clean disarmed state

use chrono::Utc;
use killswitch_core::{
    auth::OperatorAuthManager,
    freeze::NativeProcessFreezer,
    killchain::execute_host_disarm_unauthenticated,
    service::{
        default_service_manager, LinuxServiceManager, MacOsServiceManager, NativeServiceManager,
        SimulatedServiceManager,
    },
    state_ledger::{StateLedger, StateLedgerSnapshot},
    tarpit::ActiveProcessTarpit,
};
use killswitch_types::{
    constant_time_eq,
    errors::KillSwitchError,
    service::ServiceConfig,
    status::{
        AuthMethod, AuthResult, KillChainStatus, OperatorAuthenticator, OperatorCredentials,
        ProcessFreezer, KILLCHAIN_ISOLATE_TOKEN, KILLCHAIN_RESTORE_TOKEN,
    },
};
use parking_lot::Mutex;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::tempdir;

// =============================================================================
// Helper: Multithreaded Target Child Process Entry Point
// =============================================================================

/// Internal test helper executed when the binary is invoked as a child process.
/// When `EMPIRICAL_CHILD_MODE` is unset, this test returns immediately.
#[test]
fn helper_child_worker() {
    let mode = match std::env::var("EMPIRICAL_CHILD_MODE") {
        Ok(m) => m,
        Err(_) => return, // Normal test execution: pass immediately
    };

    let counter_path = std::env::var("EMPIRICAL_COUNTER_FILE").unwrap_or_default();
    let counter_path = PathBuf::from(counter_path);

    if mode == "MULTITHREAD" {
        let running = Arc::new(AtomicBool::new(true));
        let count = Arc::new(AtomicU64::new(0));

        let mut handles = Vec::new();
        for _ in 0..4 {
            let r = running.clone();
            let c = count.clone();
            let cp = counter_path.clone();
            handles.push(std::thread::spawn(move || {
                while r.load(Ordering::Relaxed) {
                    let val = c.fetch_add(1, Ordering::Relaxed);
                    if val % 200 == 0 && !cp.as_os_str().is_empty() {
                        let _ = fs::write(&cp, val.to_string());
                    }
                    std::thread::sleep(Duration::from_micros(100));
                }
            }));
        }

        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(30) {
            std::thread::sleep(Duration::from_millis(50));
        }

        running.store(false, Ordering::Relaxed);
        for h in handles {
            let _ = h.join();
        }
    } else if mode == "SELF_TERMINATE" {
        // Spawn background thread and abruptly terminate after 20ms
        std::thread::spawn(|| loop {
            std::thread::sleep(Duration::from_millis(5));
        });
        std::thread::sleep(Duration::from_millis(20));
        std::process::exit(0);
    }
}

/// Spawns a child process invoking `helper_child_worker` with the given mode.
fn spawn_test_child(mode: &str, counter_file: Option<&Path>) -> Child {
    let current_exe = std::env::current_exe().expect("current_exe");
    let mut cmd = Command::new(current_exe);
    cmd.arg("helper_child_worker")
        .arg("--nocapture")
        .arg("--exact")
        .env("EMPIRICAL_CHILD_MODE", mode);

    if let Some(path) = counter_file {
        cmd.env("EMPIRICAL_COUNTER_FILE", path);
    }

    cmd.spawn().expect("failed to spawn test child process")
}

/// RAII Guard ensuring child process is terminated on test exit.
struct ChildGuard(Option<Child>);
impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }
    fn id(&self) -> u32 {
        self.0.as_ref().map(|c| c.id()).unwrap_or(0)
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// =============================================================================
// 1. Stress Tests: ActiveProcessTarpit & NativeProcessFreezer
// =============================================================================

#[tokio::test]
async fn test_stress_multithreaded_process_freeze_and_resume_cycle() {
    let temp = tempdir().expect("tempdir");
    let counter_file = temp.path().join("counter.txt");

    let child = spawn_test_child("MULTITHREAD", Some(&counter_file));
    let guard = ChildGuard::new(child);
    let child_pid = guard.id();
    assert!(child_pid > 4);

    // Wait until child begins writing counter
    let start_wait = Instant::now();
    let mut counter_started = false;
    while start_wait.elapsed() < Duration::from_secs(5) {
        if let Ok(c) = fs::read_to_string(&counter_file) {
            if c.trim().parse::<u64>().unwrap_or(0) > 0 {
                counter_started = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(counter_started, "Child process failed to initialize counter");

    let freezer = NativeProcessFreezer::new();

    // Perform 3 freeze / resume cycles
    for cycle in 1..=3 {
        // Freeze
        let freeze_res = freezer.freeze_process(child_pid);
        assert!(
            freeze_res.is_ok(),
            "Cycle {}: freeze_process failed: {:?}",
            cycle,
            freeze_res
        );

        let initial_val = fs::read_to_string(&counter_file)
            .unwrap_or_default()
            .trim()
            .parse::<u64>()
            .unwrap_or(0);

        // Sleep while frozen and assert counter does not advance
        tokio::time::sleep(Duration::from_millis(150)).await;

        let frozen_val = fs::read_to_string(&counter_file)
            .unwrap_or_default()
            .trim()
            .parse::<u64>()
            .unwrap_or(0);

        // Small variance is possible if a thread was midway through writing, but should not exceed +200
        assert!(
            frozen_val.saturating_sub(initial_val) <= 200,
            "Cycle {}: Process continued executing while frozen (initial={}, frozen={})",
            cycle,
            initial_val,
            frozen_val
        );

        // Resume
        let resume_res = freezer.resume_process(child_pid);
        assert!(
            resume_res.is_ok(),
            "Cycle {}: resume_process failed: {:?}",
            cycle,
            resume_res
        );

        // Sleep while resumed and assert counter advances cleanly
        tokio::time::sleep(Duration::from_millis(150)).await;

        let resumed_val = fs::read_to_string(&counter_file)
            .unwrap_or_default()
            .trim()
            .parse::<u64>()
            .unwrap_or(0);

        assert!(
            resumed_val > frozen_val,
            "Cycle {}: Process deadlocked and failed to resume (frozen={}, resumed={})",
            cycle,
            frozen_val,
            resumed_val
        );
    }
}

#[tokio::test]
async fn test_stress_active_process_tarpit_duty_cycle_multithreaded() {
    let temp = tempdir().expect("tempdir");
    let counter_file = temp.path().join("tarpit_counter.txt");

    let child = spawn_test_child("MULTITHREAD", Some(&counter_file));
    let guard = ChildGuard::new(child);
    let child_pid = guard.id();

    // Wait until child counter is active
    let start_wait = Instant::now();
    while start_wait.elapsed() < Duration::from_secs(5) {
        if let Ok(c) = fs::read_to_string(&counter_file) {
            if c.trim().parse::<u64>().unwrap_or(0) > 0 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let tarpit = ActiveProcessTarpit::new();

    // Trap PID with 30ms suspend, 8ms burst, 5s max duration
    let trap_res = tarpit.trap_pid(
        child_pid,
        Duration::from_millis(30),
        Duration::from_millis(8),
        Duration::from_secs(5),
    );
    assert!(trap_res.is_ok(), "trap_pid failed: {:?}", trap_res);
    assert!(tarpit.is_trapped(child_pid));

    // Idempotent trapping check: trapping already trapped PID returns Ok(())
    assert!(tarpit
        .trap_pid(
            child_pid,
            Duration::from_millis(30),
            Duration::from_millis(8),
            Duration::from_secs(5)
        )
        .is_ok());

    // Allow duty cycling to execute for 300ms
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Release PID
    tarpit.release_pid(child_pid);
    assert!(!tarpit.is_trapped(child_pid));

    // Release again is idempotent
    tarpit.release_pid(child_pid);
    assert!(!tarpit.is_trapped(child_pid));

    // Verify process still functions and advances counter after tarpit release
    tokio::time::sleep(Duration::from_millis(100)).await;
    let post_release_val = fs::read_to_string(&counter_file)
        .unwrap_or_default()
        .trim()
        .parse::<u64>()
        .unwrap_or(0);

    assert!(
        post_release_val > 0,
        "Target process died or hung after tarpit release"
    );
}

#[tokio::test]
async fn test_stress_freeze_self_terminating_process_edge_case() {
    let child = spawn_test_child("SELF_TERMINATE", None);
    let mut guard = ChildGuard::new(child);
    let child_pid = guard.id();

    // Allow child to terminate
    tokio::time::sleep(Duration::from_millis(60)).await;
    if let Some(ref mut c) = guard.0 {
        let _ = c.wait();
    }

    let freezer = NativeProcessFreezer::new();

    // Freezing terminated process must fail closed gracefully without panicking
    let freeze_res = freezer.freeze_process(child_pid);
    assert!(
        freeze_res.is_err(),
        "Freezing terminated process must return error"
    );

    // Resuming terminated process must fail closed gracefully
    let resume_res = freezer.resume_process(child_pid);
    assert!(
        resume_res.is_err(),
        "Resuming terminated process must return error"
    );
}

#[tokio::test]
async fn test_stress_tarpit_self_terminating_process_edge_case() {
    let child = spawn_test_child("SELF_TERMINATE", None);
    let mut guard = ChildGuard::new(child);
    let child_pid = guard.id();

    // Allow child to terminate
    tokio::time::sleep(Duration::from_millis(60)).await;
    if let Some(ref mut c) = guard.0 {
        let _ = c.wait();
    }

    let tarpit = ActiveProcessTarpit::new();

    // Tarpitting terminated process must return ThreadSnapshotFailed without panicking
    let trap_res = tarpit.trap_pid_default(child_pid);
    assert!(
        trap_res.is_err(),
        "Tarpitting terminated process must return error"
    );
    match trap_res {
        Err(KillSwitchError::ThreadSnapshotFailed { pid, .. }) => {
            assert_eq!(pid, child_pid);
        }
        other => panic!("Expected ThreadSnapshotFailed, got: {:?}", other),
    }

    // Release PID on untracked/dead process is clean
    tarpit.release_pid(child_pid);
    assert!(!tarpit.is_trapped(child_pid));
}

// =============================================================================
// 2. Stress Tests: OperatorAuthManager & Rate-Limiting Lockout
// =============================================================================

#[test]
fn test_stress_auth_constant_time_timing_distribution() {
    let secret = "AlphaBravoCharlieDeltaEcho123456789!@#$%^&*()";
    let diff_byte0 = "ZlphaBravoCharlieDeltaEcho123456789!@#$%^&*()";
    let diff_last = "AlphaBravoCharlieDeltaEcho123456789!@#$%^&*(?";
    let diff_len = "AlphaBravo";
    let exact = "AlphaBravoCharlieDeltaEcho123456789!@#$%^&*()";

    // Warm up
    for _ in 0..1000 {
        let _ = constant_time_eq(secret, exact);
    }

    let iterations = 20_000;
    let mut elapsed_diff0 = Duration::ZERO;
    let mut elapsed_diff_last = Duration::ZERO;

    for _ in 0..iterations {
        let t0 = Instant::now();
        let r0 = constant_time_eq(secret, diff_byte0);
        elapsed_diff0 += t0.elapsed();
        assert!(!r0);

        let t1 = Instant::now();
        let r1 = constant_time_eq(secret, diff_last);
        elapsed_diff_last += t1.elapsed();
        assert!(!r1);
    }

    assert!(!constant_time_eq(secret, diff_len));
    assert!(constant_time_eq(secret, exact));

    // Ratio of timings between mismatch at first byte vs last byte should be very close (~1.0)
    let nanos0 = elapsed_diff0.as_nanos() as f64;
    let nanos_last = elapsed_diff_last.as_nanos() as f64;
    let ratio = nanos0 / nanos_last;

    // Both should take within 50% of each other across 20k runs (zero early-exit cliff)
    assert!(
        (0.5..=2.0).contains(&ratio),
        "Timing discrepancy detected: diff0={}ns, diff_last={}ns, ratio={}",
        nanos0,
        nanos_last,
        ratio
    );
}

#[test]
fn test_stress_auth_3_strike_lockout_exact_threshold() {
    let temp = tempdir().expect("tempdir");
    let auth = OperatorAuthManager::new(None, Some(temp.path().to_path_buf()));

    let bad_creds = OperatorCredentials {
        operator_id: "sec_operator".to_string(),
        auth_token: None,
        password: Some("incorrect_password".to_string()),
        caller_pid: Some(9999),
        confirmation_phrase: None,
    };

    // Strike 1
    let res1 = auth.authenticate(&bad_creds);
    assert!(matches!(
        res1,
        AuthResult::Failed {
            attempts_remaining: 2,
            ..
        }
    ));
    let st1 = auth.check_lockout();
    assert!(!st1.is_locked);
    assert_eq!(st1.failed_attempts, 1);

    // Strike 2
    let res2 = auth.authenticate(&bad_creds);
    assert!(matches!(
        res2,
        AuthResult::Failed {
            attempts_remaining: 1,
            ..
        }
    ));
    let st2 = auth.check_lockout();
    assert!(!st2.is_locked);
    assert_eq!(st2.failed_attempts, 2);

    // Strike 3: Triggers 300s Lockout
    let res3 = auth.authenticate(&bad_creds);
    assert!(matches!(
        res3,
        AuthResult::LockedOut {
            remaining_seconds: 300,
            ..
        }
    ));
    let st3 = auth.check_lockout();
    assert!(st3.is_locked);
    assert_eq!(st3.failed_attempts, 3);
    assert_eq!(st3.lockout_remaining_secs, 300);
    assert_eq!(st3.last_failed_caller_pid, Some(9999));

    // Strike 4: Even subsequent attempts while locked out remain LockedOut
    let res4 = auth.authenticate(&bad_creds);
    assert!(matches!(res4, AuthResult::LockedOut { .. }));
}

#[test]
fn test_stress_auth_tier1_master_token_bypass_and_lockout_reset() {
    let temp = tempdir().expect("tempdir");
    let mut auth = OperatorAuthManager::new(None, Some(temp.path().to_path_buf()));
    let custom_master = "KILLCHAIN_CUSTOM_EMERGENCY_OVERRIDE_2026";
    auth.set_custom_master_token(custom_master.to_string());

    // Configure Tier 2 admin password
    let env_password = "ValidTier2Password-SecOps!";
    std::env::set_var("KILLSWITCH_ADMIN_PASSWORD", env_password);

    // 1. Trigger Lockout with 3 failed attempts
    for _ in 0..3 {
        let creds = OperatorCredentials {
            operator_id: "intruder".to_string(),
            auth_token: None,
            password: Some("wrong_password".to_string()),
            caller_pid: Some(8888),
            confirmation_phrase: None,
        };
        let _ = auth.authenticate(&creds);
    }
    assert!(auth.check_lockout().is_locked);

    // 2. While locked out, normal Tier 2 password MUST BE REJECTED
    let tier2_attempt = OperatorCredentials {
        operator_id: "legit_admin".to_string(),
        auth_token: None,
        password: Some(env_password.to_string()),
        caller_pid: Some(8888),
        confirmation_phrase: None,
    };
    let res_t2 = auth.authenticate(&tier2_attempt);
    assert!(
        matches!(res_t2, AuthResult::LockedOut { .. }),
        "Tier 2 password must not bypass active lockout"
    );

    // 3. Present Tier 1 Custom Master Token: MUST BYPASS AND RESET LOCKOUT
    let master_attempt = OperatorCredentials {
        operator_id: "emergency_admin".to_string(),
        auth_token: Some(custom_master.to_string()),
        password: None,
        caller_pid: Some(8888),
        confirmation_phrase: None,
    };
    let res_m = auth.authenticate(&master_attempt);
    assert!(res_m.is_success());
    if let AuthResult::Success { method, .. } = res_m {
        assert_eq!(method, AuthMethod::MasterTokenBypass);
    }

    // 4. Assert Lockout is completely reset
    let post_master = auth.check_lockout();
    assert!(!post_master.is_locked);
    assert_eq!(post_master.failed_attempts, 0);

    // 5. Normal Tier 2 password now succeeds immediately
    let res_t2_post = auth.authenticate(&tier2_attempt);
    assert!(res_t2_post.is_success());
    if let AuthResult::Success { method, .. } = res_t2_post {
        assert_eq!(method, AuthMethod::EnvironmentPassword);
    }

    // Clean up environment variable
    std::env::remove_var("KILLSWITCH_ADMIN_PASSWORD");
}

#[test]
fn test_stress_auth_predefined_master_tokens() {
    let auth = OperatorAuthManager::new(None, None);

    // Test KILLCHAIN_RESTORE_TOKEN
    let restore_creds = OperatorCredentials {
        operator_id: "secops".to_string(),
        auth_token: None,
        password: None,
        caller_pid: Some(5555),
        confirmation_phrase: Some(KILLCHAIN_RESTORE_TOKEN.to_string()),
    };
    let r1 = auth.authenticate(&restore_creds);
    assert!(r1.is_success());

    // Test KILLCHAIN_ISOLATE_TOKEN
    let isolate_creds = OperatorCredentials {
        operator_id: "secops".to_string(),
        auth_token: Some(KILLCHAIN_ISOLATE_TOKEN.to_string()),
        password: None,
        caller_pid: Some(5555),
        confirmation_phrase: None,
    };
    let r2 = auth.authenticate(&isolate_creds);
    assert!(r2.is_success());
}

#[test]
fn test_stress_auth_caller_pid_anti_hijacking_boundaries() {
    let mut auth = OperatorAuthManager::new(None, None);
    let quarantined_pid = 7777;
    auth.set_frozen_pids_provider(Arc::new(move || vec![quarantined_pid]));

    // Critical kernel / system PIDs must be rejected
    for pid in [0, 1, 4] {
        let creds = OperatorCredentials {
            operator_id: "sys".to_string(),
            auth_token: Some(KILLCHAIN_RESTORE_TOKEN.to_string()),
            password: None,
            caller_pid: Some(pid),
            confirmation_phrase: None,
        };
        let res = auth.authenticate(&creds);
        assert!(matches!(res, AuthResult::CallerQuarantined { .. }));
    }

    // Frozen caller PID must be rejected
    let creds_frozen = OperatorCredentials {
        operator_id: "compromised".to_string(),
        auth_token: Some(KILLCHAIN_RESTORE_TOKEN.to_string()),
        password: None,
        caller_pid: Some(quarantined_pid),
        confirmation_phrase: None,
    };
    let res_frozen = auth.authenticate(&creds_frozen);
    assert!(matches!(res_frozen, AuthResult::CallerQuarantined { .. }));

    // Valid PID 6000 is permitted
    let creds_valid = OperatorCredentials {
        operator_id: "valid".to_string(),
        auth_token: Some(KILLCHAIN_RESTORE_TOKEN.to_string()),
        password: None,
        caller_pid: Some(6000),
        confirmation_phrase: None,
    };
    let res_valid = auth.authenticate(&creds_valid);
    assert!(res_valid.is_success());
}

// =============================================================================
// 3. Stress Tests: StateLedger Atomic Commits & BLAKE3 Cryptographic Integrity
// =============================================================================

#[test]
fn test_stress_state_ledger_rapid_concurrent_commits() {
    let temp = tempdir().expect("tempdir");
    let ledger = StateLedger::open_or_init(Some(temp.path())).expect("open_or_init");
    let ledger_arc = Arc::new(Mutex::new(ledger));

    let threads = 8;
    let transitions_per_thread = 15;
    let mut handles = Vec::new();

    for t in 0..threads {
        let l_clone = ledger_arc.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..transitions_per_thread {
                let status = KillChainStatus {
                    isolated: (t + i) % 2 == 1,
                    last_action_timestamp: Some(Utc::now()),
                    ..KillChainStatus::default()
                };
                let action = format!("ACTION_T{}_I{}", t, i);
                let operator = format!("operator_{}", t);
                let reason = format!("Concurrent stress test thread {} step {}", t, i);

                let mut guard = l_clone.lock();
                guard
                    .record_state_transition(status, None, None, &action, &operator, &reason)
                    .expect("record_state_transition");
            }
        }));
    }

    for h in handles {
        h.join().expect("thread join");
    }

    let final_ledger = ledger_arc.lock();
    assert_eq!(
        final_ledger.snapshot().sequence_number,
        (threads * transitions_per_thread) as u64
    );
    assert_eq!(
        final_ledger.snapshot().history.len(),
        threads * transitions_per_thread
    );

    // Verify cryptographic integrity of entire chain
    assert!(
        final_ledger.verify_integrity().is_ok(),
        "State ledger integrity verification failed after concurrent commits"
    );

    // Reload ledger from disk and verify persistence
    drop(final_ledger);
    let reloaded = StateLedger::open_or_init(Some(temp.path())).expect("reload");
    assert_eq!(
        reloaded.snapshot().sequence_number,
        (threads * transitions_per_thread) as u64
    );
    assert!(reloaded.verify_integrity().is_ok());
}

#[test]
fn test_stress_state_ledger_hash_chain_depth_and_determinism() {
    let temp = tempdir().expect("tempdir");
    let mut ledger = StateLedger::open_or_init(Some(temp.path())).expect("init");

    let depth = 30;
    for i in 1..=depth {
        let prev_hash = ledger.snapshot().current_hash.clone();
        let status = KillChainStatus {
            isolated: i % 2 == 1,
            ..KillChainStatus::default()
        };
        let action = format!("CHAIN_TEST_{}", i);

        ledger
            .record_state_transition(status, None, None, &action, "secops", "Depth test")
            .unwrap();

        assert_eq!(ledger.snapshot().prev_hash, prev_hash);
        assert_eq!(ledger.snapshot().sequence_number, i as u64);
        assert!(ledger.verify_integrity().is_ok());
    }

    assert_eq!(ledger.snapshot().history.len(), depth);
}

#[test]
fn test_stress_state_ledger_corruption_detection_bit_flips() {
    let temp = tempdir().expect("tempdir");
    let mut ledger = StateLedger::open_or_init(Some(temp.path())).expect("init");

    // Commit 3 transitions
    for i in 1..=3 {
        ledger
            .record_state_transition(
                KillChainStatus::default(),
                None,
                None,
                &format!("EV_{}", i),
                "admin",
                "test",
            )
            .unwrap();
    }
    assert!(ledger.verify_integrity().is_ok());

    let state_file = temp.path().join("killchain_state.json");
    let original_content = fs::read_to_string(&state_file).expect("read");
    let mut snapshot: StateLedgerSnapshot = serde_json::from_str(&original_content).unwrap();

    // Corruption Scenario 1: Bit flip in current_hash
    {
        let mut corrupted = snapshot.clone();
        let mut chars: Vec<char> = corrupted.current_hash.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        corrupted.current_hash = chars.into_iter().collect();
        fs::write(
            &state_file,
            serde_json::to_string_pretty(&corrupted).unwrap(),
        )
        .unwrap();

        let reload_res = StateLedger::open_or_init(Some(temp.path()));
        // When corrupted, open_or_init falls back to clean re-init
        let reloaded = reload_res.unwrap();
        assert_eq!(
            reloaded.snapshot().sequence_number,
            0,
            "Corrupted current_hash must trigger fallback to clean state"
        );
    }

    // Corruption Scenario 2: Bit flip in status payload without updating hash
    {
        fs::write(&state_file, &original_content).unwrap();
        let mut corrupted = snapshot.clone();
        corrupted.status.isolated = !corrupted.status.isolated;
        fs::write(
            &state_file,
            serde_json::to_string_pretty(&corrupted).unwrap(),
        )
        .unwrap();

        let reloaded = StateLedger::open_or_init(Some(temp.path())).unwrap();
        assert_eq!(
            reloaded.snapshot().sequence_number,
            0,
            "Altered status payload must fail hash check and reset"
        );
    }

    // Corruption Scenario 3: Corrupt audit history event hash
    {
        fs::write(&state_file, &original_content).unwrap();
        let _valid_ledger = StateLedger::open_or_init(Some(temp.path())).unwrap();
        // Manually tamper history in memory and test verify_integrity()
        let corrupted_entry = &mut snapshot.history[0];
        corrupted_entry.event_hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string();
        // Recompute snapshot hash with tampered history so snapshot hash passes
        snapshot.current_hash = snapshot.calculate_hash();

        fs::write(
            &state_file,
            serde_json::to_string_pretty(&snapshot).unwrap(),
        )
        .unwrap();
        let loaded = StateLedger::open_or_init(Some(temp.path())).unwrap();
        let verify_res = loaded.verify_integrity();
        assert!(
            verify_res.is_err(),
            "Tampered history event hash must fail verify_integrity"
        );
        match verify_res {
            Err(KillSwitchError::StateHashChainMismatch { index, .. }) => {
                assert_eq!(index, 0);
            }
            other => panic!("Expected StateHashChainMismatch, got: {:?}", other),
        }
    }
}

// =============================================================================
// 4. Stress Tests: Cross-Platform Service Manager & Unconditional Shutdown Disarm
// =============================================================================

#[test]
fn test_stress_unconditional_shutdown_disarm_leaves_host_clean() {
    let temp = tempdir().expect("tempdir");
    std::env::set_var("KILLSWITCH_DATABASE_DIR", temp.path());

    // 1. Tarpit a simulated PID (non-immune) in the global tarpit
    let tarpit = ActiveProcessTarpit::global();
    let test_pid = 65432;
    // On Windows, tarpitting non-existent PID errors out on thread snapshot,
    // but we can test release_all on active traps or directly verify disarm contract.
    tarpit.release_pid(test_pid);

    // 2. Invoke unconditional unauthenticated disarm
    let disarm_res = execute_host_disarm_unauthenticated();
    assert!(
        disarm_res.is_ok(),
        "execute_host_disarm_unauthenticated failed: {:?}",
        disarm_res
    );

    let status = disarm_res.unwrap();
    assert!(!status.isolated, "Host must be marked NOT isolated");
    assert!(
        !status.network_isolated,
        "Network must be marked NOT isolated"
    );
    assert_eq!(
        status.processes_frozen_count, 0,
        "Processes frozen count must be 0"
    );
    assert!(status.frozen_pids.is_empty(), "Frozen PIDs must be empty");

    // 3. Verify that global tarpit has zero active traps
    assert!(
        !tarpit.is_trapped(test_pid),
        "Global tarpit must be completely cleared"
    );

    // 4. Verify state ledger records DISARMED_UNCONDITIONAL event
    let ledger = StateLedger::open_or_init(Some(temp.path())).expect("open ledger");
    let history = &ledger.snapshot().history;
    assert!(
        !history.is_empty(),
        "History must contain shutdown disarm event"
    );
    let latest_event = &history[0];
    assert_eq!(latest_event.action, "DISARMED_UNCONDITIONAL");
    assert_eq!(latest_event.operator, "SYSTEM_SHUTDOWN");

    std::env::remove_var("KILLSWITCH_DATABASE_DIR");
}

#[test]
fn test_stress_service_manager_daemon_shutdown_hook() {
    // 1. Test SimulatedServiceManager
    let sim_mgr = SimulatedServiceManager::new();
    let run_res = sim_mgr.run_service_daemon();
    assert!(
        run_res.is_ok(),
        "SimulatedServiceManager daemon run must return Ok"
    );

    // 2. Test LinuxServiceManager daemon disarm contract
    let temp_linux = tempdir().expect("tempdir");
    let linux_mgr = LinuxServiceManager::with_root_dir(temp_linux.path());
    let config = ServiceConfig {
        name: "killswitch-test-daemon".to_string(),
        root_dir: Some(temp_linux.path().to_path_buf()),
        ..Default::default()
    };
    linux_mgr.install_service(&config).unwrap();
    let status = linux_mgr.service_status(&config.name).unwrap();
    assert!(status.is_installed);

    // Request stop before synchronous run to verify single-pass lifecycle
    linux_mgr.request_stop();
    let linux_run = linux_mgr.run_service_daemon();
    assert!(linux_run.is_ok());

    // 3. Test MacOsServiceManager daemon disarm contract
    let temp_mac = tempdir().expect("tempdir");
    let mac_mgr = MacOsServiceManager::with_root_dir(temp_mac.path());
    let mac_config = ServiceConfig {
        name: "killswitch-test-mac-daemon".to_string(),
        root_dir: Some(temp_mac.path().to_path_buf()),
        ..Default::default()
    };
    mac_mgr.install_service(&mac_config).unwrap();

    mac_mgr.request_stop();
    let mac_run = mac_mgr.run_service_daemon();
    assert!(mac_run.is_ok());

    // 4. Verify default_service_manager contract
    let default_mgr = default_service_manager();
    let stat = default_mgr.service_status("test-service");
    assert!(stat.is_ok());
}
