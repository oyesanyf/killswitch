//! Empirical Challenge Test Suite SEC-5-1:
//! Siquery Relational SQL Host Discovery Engine Adversarial Challenge.
//!
//! Author: challenger_sec5_1 (teamwork_challenger)
//!
//! Stress-tests:
//! 1. SQL injection, semicolon query stacking, CTE mutations, ATTACH, and writable PRAGMA bypasses.
//! 2. 16-thread ring buffer concurrent flooding (10,000+ events) and lock contention safety.
//! 3. Table & schema robustness across all 41 tables with complex SQL and graceful error recovery.
//! 4. 12-sweep EDR audit under adversarial host states, asserting PID <= 4 and kernel anchors are never quarantined.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use chrono::Utc;
use killswitch_core::exec_sensor::{simulate_exec_event, ExecEvent};
use killswitch_core::freeze::NativeProcessFreezer;
use killswitch_core::killchain::is_immutable_os_kernel_pid;
use killswitch_telemetry::agent_hooks::GLOBAL_CORRELATOR;
use killswitch_telemetry::circumvention::{DenialPatternKind, DynamicDenialSignal};
use killswitch_telemetry::semantic_command::PrivilegeEquivalenceClass;
use killswitch_telemetry::siquery::{
    record_live_file_event, FileEventRecord, SiqueryEngine, LIVE_FILE_EVENTS,
};
use killswitch_types::ProcessFreezer;
use parking_lot::Mutex;

/// Global test lock to prevent parallel test races on the shared `LIVE_FILE_EVENTS` static buffer.
static SHARED_BUFFER_LOCK: Mutex<()> = Mutex::new(());

// ============================================================================
// 1. SQL INJECTION & MUTATING STATEMENT BYPASSES
// ============================================================================

#[test]
fn test_challenge_sql_injection_semicolon_stacking() {
    let engine = SiqueryEngine::new();

    // Baseline: Verify processes table is readable
    let base = engine
        .execute_query("SELECT count(*) as total FROM processes;")
        .expect("Baseline processes query must succeed");
    let _initial_count = base[0].get("total").and_then(|v| v.as_i64()).unwrap_or(0);

    // Stacking Attack 1: DROP TABLE via semicolon
    let drop_stacked = "SELECT 1; DROP TABLE processes;";
    let res1 = engine.execute_query(drop_stacked);
    // Even if first statement executes, processes table MUST NOT be dropped
    assert!(res1.is_ok(), "First SELECT statement in stacked query prepared");
    let check1 = engine.execute_query("SELECT count(*) as total FROM processes;");
    assert!(check1.is_ok(), "processes table MUST exist and not be dropped");
    let check1_count = check1.unwrap()[0].get("total").and_then(|v| v.as_i64()).unwrap_or(0);
    assert!(check1_count >= 10, "Processes table must remain populated (found {})", check1_count);

    // Stacking Attack 2: INSERT via semicolon
    let insert_stacked = "SELECT 1; INSERT INTO processes(pid, name) VALUES (999999, 'evil');";
    let _res2 = engine.execute_query(insert_stacked);
    let check2 = engine
        .execute_query("SELECT count(*) as total FROM processes WHERE pid = 999999;")
        .expect("Query for injected row");
    assert_eq!(
        check2[0].get("total").and_then(|v| v.as_i64()).unwrap_or(0),
        0,
        "Injected row must NOT exist"
    );

    // Stacking Attack 3: DELETE via semicolon
    let delete_stacked = "SELECT 1; DELETE FROM processes;";
    let _res3 = engine.execute_query(delete_stacked);
    let check3 = engine
        .execute_query("SELECT count(*) as total FROM processes;")
        .expect("Query processes after delete attempt");
    let check3_count = check3[0].get("total").and_then(|v| v.as_i64()).unwrap_or(0);
    assert!(
        check3_count >= 10,
        "Processes table must NOT be emptied by stacked DELETE (found {})",
        check3_count
    );

    // Stacking Attack 4: CREATE TABLE via semicolon
    let create_stacked = "SELECT 1; CREATE TABLE pwned_table (id INT);";
    let _res4 = engine.execute_query(create_stacked);
    let check4 = engine.execute_query("SELECT * FROM pwned_table;");
    assert!(
        check4.is_err(),
        "pwned_table must NOT have been created by stacked query"
    );
}

#[test]
fn test_challenge_mutating_prefix_case_and_whitespace() {
    let engine = SiqueryEngine::new();

    let attack_vectors = [
        // Case variations
        "dRoP table processes;",
        "DROP TABLE processes;",
        "iNsErT iNtO processes (pid) VALUES (1);",
        "INSERT INTO processes (pid) VALUES (1);",
        "uPdAtE processes SET pid = 1;",
        "UPDATE processes SET pid = 1;",
        "dElEtE FROM processes;",
        "DELETE FROM processes;",
        "cReAtE TABLE hacked (id INT);",
        "CREATE TABLE hacked (id INT);",
        "aLtEr TABLE processes ADD COLUMN x TEXT;",
        "ALTER TABLE processes ADD COLUMN x TEXT;",
        "rEpLaCe INTO processes (pid) VALUES (1);",
        "REPLACE INTO processes (pid) VALUES (1);",
        "tRuNcAtE TABLE processes;",
        "TRUNCATE TABLE processes;",
        "aTtAcH DATABASE 'evil.db' AS evil;",
        "ATTACH DATABASE 'evil.db' AS evil;",
        "dEtAcH DATABASE evil;",
        "DETACH DATABASE evil;",
        // Leading whitespace variations
        "   \r\n\t  ALTER TABLE processes ADD COLUMN x TEXT;",
        "\n\t  dRoP TABLE processes;",
        "   INSERT INTO processes (pid) VALUES (1);",
        "\r\n   DELETE FROM processes;",
        " \t CREATE TABLE hacked (id INT);",
        "   ATTACH DATABASE 'foo' AS bar;",
    ];

    for attack in &attack_vectors {
        let err = engine
            .execute_query(attack)
            .expect_err(&format!("Mutating query '{}' must be rejected", attack));
        assert!(
            err.contains("Mutating SQL statements are forbidden (read-only query engine)"),
            "Attack '{}' produced unexpected error: {}",
            attack,
            err
        );
    }
}

#[test]
fn test_challenge_comment_obfuscation_authorizer_bypass() {
    let engine = SiqueryEngine::new();

    // Attackers frequently use SQL comments to bypass naive string-prefix filters.
    // Siquery's Guard 2 (SQLite Authorizer Callback) and Guard 4 (VDBE Readonly)
    // must strictly intercept and deny these actions even when comment-wrapped.
    let comment_attacks = [
        "/* comment */ DROP TABLE processes;",
        "/* multi \n line \n comment */ CREATE TABLE evil (x INT);",
        "/* comment */ INSERT INTO processes (pid) VALUES (99999);",
        "/* comment */ UPDATE processes SET pid = 1;",
        "/* comment */ DELETE FROM processes;",
        "/* comment */ ALTER TABLE processes ADD COLUMN evil TEXT;",
        "/* comment */ ATTACH DATABASE 'evil.db' AS evil;",
        "/* comment */ DETACH DATABASE evil;",
        "-- inline comment\nDROP TABLE processes;",
        "-- inline comment\nDELETE FROM processes;",
        "-- inline comment\nATTACH 'evil.db' AS evil;",
        "/* comment */ REPLACE INTO processes (pid) VALUES (1);",
    ];

    for attack in &comment_attacks {
        let res = engine.execute_query(attack);
        assert!(
            res.is_err(),
            "Comment-obfuscated attack '{}' MUST be rejected, but succeeded with: {:?}",
            attack,
            res
        );
    }

    // Verify processes table was not affected
    let check = engine.execute_query("SELECT count(*) as total FROM processes;");
    assert!(check.is_ok(), "processes table must remain intact");
}

#[test]
fn test_challenge_cte_mutating_bypass() {
    let engine = SiqueryEngine::new();

    let cte_attacks = [
        // CTE with mutation in inner statement
        "WITH mutated AS (INSERT INTO processes(pid) VALUES (1) RETURNING pid) SELECT * FROM mutated;",
        "WITH cte AS (SELECT 1) INSERT INTO processes(pid) VALUES (1);",
        "WITH cte AS (SELECT 1) UPDATE processes SET pid = 1;",
        "WITH cte AS (SELECT 1) DELETE FROM processes;",
        "WITH cte AS (SELECT 1) DROP TABLE processes;",
        "WITH RECURSIVE evil(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM evil WHERE x < 5) INSERT INTO processes(pid) SELECT x FROM evil;",
    ];

    for attack in &cte_attacks {
        let res = engine.execute_query(attack);
        assert!(
            res.is_err(),
            "CTE mutating attack '{}' MUST be rejected, but succeeded with: {:?}",
            attack,
            res
        );
    }
}

#[test]
fn test_challenge_sqlite_attach_and_load_extension_bypass() {
    let engine = SiqueryEngine::new();

    // ATTACH attempts
    let attach_attacks = [
        "ATTACH 'pwn.db' AS pwn;",
        "ATTACH DATABASE ':memory:' AS pwn;",
        "/* comment */ ATTACH ':memory:' AS pwn;",
        "SELECT 1; ATTACH ':memory:' AS pwn;",
    ];

    for attack in &attach_attacks {
        let _res = engine.execute_query(attack);
        // Either error or second statement ignored: verify pwn is not an attached database
        let check = engine.execute_query("PRAGMA database_list;");
        if let Ok(dbs) = check {
            for db in dbs {
                let name = db.get("name").and_then(|v| v.as_str()).unwrap_or("");
                assert_ne!(name, "pwn", "Database 'pwn' must NOT be attached");
            }
        }
    }

    // load_extension attempts
    let ext_attacks = [
        "SELECT load_extension('evil');",
        "SELECT load_extension('evil.dll', 'entry');",
        "SELECT load_extension('/tmp/evil.so');",
    ];

    for attack in &ext_attacks {
        let res = engine.execute_query(attack);
        assert!(
            res.is_err(),
            "load_extension attempt '{}' MUST fail",
            attack
        );
    }
}

#[test]
fn test_challenge_writable_pragma_bypass() {
    let engine = SiqueryEngine::new();

    // Querying PRAGMA writable_schema
    let _ = engine.execute_query("PRAGMA writable_schema = 1;");

    // Attempt to mutate sqlite_master directly
    let mutate_master_attacks = [
        "UPDATE sqlite_master SET sql = 'CREATE TABLE foo(x)' WHERE type = 'table';",
        "/* comment */ UPDATE sqlite_master SET sql = 'CREATE TABLE foo(x)' WHERE type = 'table';",
        "INSERT INTO sqlite_master (type, name, tbl_name, rootpage, sql) VALUES ('table', 'evil', 'evil', 0, 'CREATE TABLE evil(x)');",
        "DELETE FROM sqlite_master;",
    ];

    for attack in &mutate_master_attacks {
        let res = engine.execute_query(attack);
        assert!(
            res.is_err(),
            "Direct sqlite_master mutation '{}' MUST be rejected",
            attack
        );
    }
}

#[test]
fn test_challenge_parameterized_injection_sanitization() {
    let _guard = SHARED_BUFFER_LOCK.lock();
    let engine = SiqueryEngine::new();

    // Insert FileEventRecord containing adversarial SQL injection characters
    let malicious_path = "C:\\Windows\\System32\\'; DROP TABLE file_events; --";
    let malicious_action = "write'; DELETE FROM processes; --";
    let malicious_proc = "cmd.exe' OR '1'='1";
    let malicious_hash = "deadbeef'; DROP VIEW live_file_events; --";

    record_live_file_event(FileEventRecord {
        target_path: malicious_path.to_string(),
        action: malicious_action.to_string(),
        pid: 77777,
        process_name: malicious_proc.to_string(),
        sha256: malicious_hash.to_string(),
        time: 1700009999,
    });

    // Query file_events table
    let rows = engine
        .execute_query("SELECT target_path, action, pid, process_name, sha256 FROM file_events WHERE pid = 77777;")
        .expect("Query with injected row must succeed");
    assert_eq!(rows.len(), 1, "Must find exactly 1 record");
    assert_eq!(
        rows[0].get("target_path").and_then(|v| v.as_str()),
        Some(malicious_path),
        "Adversarial path must be safely preserved without SQL execution"
    );
    assert_eq!(
        rows[0].get("action").and_then(|v| v.as_str()),
        Some(malicious_action)
    );

    // Verify file_events and live_file_events still exist
    let verify_tbl = engine.execute_query("SELECT count(*) FROM file_events;");
    assert!(verify_tbl.is_ok(), "file_events table must remain intact");
    let verify_view = engine.execute_query("SELECT count(*) FROM live_file_events;");
    assert!(verify_view.is_ok(), "live_file_events view must remain intact");
}

// ============================================================================
// 2. MULTI-THREADED RING BUFFER FLOOD & CONTENTION
// ============================================================================

#[test]
fn test_challenge_multithreaded_ring_buffer_flood_and_contention() {
    let _guard = SHARED_BUFFER_LOCK.lock();
    let engine = Arc::new(SiqueryEngine::new());
    let write_counter = Arc::new(AtomicUsize::new(0));
    let read_counter = Arc::new(AtomicUsize::new(0));
    let monotonic_seq = Arc::new(AtomicUsize::new(0));
    let stop_signal = Arc::new(AtomicBool::new(false));

    let mut writer_handles = Vec::new();
    let mut reader_handles = Vec::new();

    // 16 Concurrent Writers to LIVE_FILE_EVENTS (10,000+ events total: 16 * 700 = 11,200 events)
    for thread_idx in 0..16 {
        let wc = write_counter.clone();
        let seq = monotonic_seq.clone();
        writer_handles.push(thread::spawn(move || {
            for i in 0..700 {
                let s = seq.fetch_add(1, Ordering::SeqCst);
                record_live_file_event(FileEventRecord {
                    target_path: format!("C:\\flood\\t{}_file_{}.log", thread_idx, i),
                    action: "write".to_string(),
                    pid: (thread_idx * 1000 + i) as i64,
                    process_name: format!("flood_proc_{}.exe", thread_idx),
                    sha256: format!("hash_{:04}_{:04}", thread_idx, i),
                    time: 1700000000 + (s as i64),
                });
                wc.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    // 8 Concurrent Writers to EXEC_SENSOR_BUFFER (8 * 500 = 4,000 events)
    for thread_idx in 0..8 {
        writer_handles.push(thread::spawn(move || {
            for i in 0..500 {
                simulate_exec_event(ExecEvent {
                    pid: 100000 + (thread_idx * 1000 + i) as u32,
                    ppid: 1000,
                    image_path: format!("C:\\flood\\exec_{}.exe", thread_idx),
                    cmdline: format!("exec_{}.exe --iter {}", thread_idx, i),
                    timestamp_ns: 1000000000 + (thread_idx * 1000 + i) as u64,
                    uid: Some(1000),
                    euid: Some(1000),
                    exit_code: Some(0),
                });
            }
        }));
    }

    // 8 Concurrent Readers querying live_file_events and exec_events
    for _ in 0..8 {
        let eng = engine.clone();
        let rc = read_counter.clone();
        let stop = stop_signal.clone();
        reader_handles.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let res1 = eng.execute_query("SELECT count(*) as c FROM live_file_events;");
                assert!(res1.is_ok(), "Query to live_file_events must succeed under contention");

                let res2 = eng.execute_query("SELECT count(*) as c FROM exec_events;");
                assert!(res2.is_ok(), "Query to exec_events must succeed under contention");

                rc.fetch_add(1, Ordering::SeqCst);
                thread::yield_now();
            }
        }));
    }

    // Wait for writer threads to finish
    for w in writer_handles {
        w.join().expect("Writer thread must not panic");
    }

    // Signal readers to stop
    stop_signal.store(true, Ordering::SeqCst);
    for r in reader_handles {
        r.join().expect("Reader thread must not panic");
    }

    // Assert total writes exceeded 10,000
    let total_file_writes = write_counter.load(Ordering::SeqCst);
    assert_eq!(total_file_writes, 11200, "Must have written 11,200 file events");
    assert!(read_counter.load(Ordering::SeqCst) > 0, "Readers must have completed queries");

    // Assert ring buffer exact capacity cap (1024)
    let q = LIVE_FILE_EVENTS.read();
    assert_eq!(q.len(), 1024, "LIVE_FILE_EVENTS must be capped at 1024 entries");

    // Verify FIFO eviction: front timestamp must be strictly less than back timestamp
    let front_time = q.front().unwrap().time;
    let back_time = q.back().unwrap().time;
    assert!(
        front_time < back_time,
        "FIFO eviction invariant: front time {} must be earlier than back time {}",
        front_time,
        back_time
    );
    drop(q);

    // Verify Siquery can still query without deadlock
    let verify = engine
        .execute_query("SELECT count(*) as total FROM live_file_events;")
        .expect("Post-flood query must succeed");
    let count = verify[0].get("total").and_then(|v| v.as_i64()).unwrap_or(0);
    assert!(count >= 1024, "Siquery must see at least 1024 events");
}

// ============================================================================
// 3. TABLE & SCHEMA ROBUSTNESS ACROSS ALL 41 TABLES
// ============================================================================

#[test]
fn test_challenge_schema_robustness_all_41_tables() {
    let engine = SiqueryEngine::new();
    let tables = SiqueryEngine::list_tables();

    assert!(
        tables.len() >= 41,
        "Engine must expose >= 41 tables, found {}",
        tables.len()
    );

    // Verify every single table and view can be queried without crashing or failing
    for tbl in tables {
        let sql = format!("SELECT * FROM {} LIMIT 2;", tbl);
        let res = engine.execute_query(&sql);
        assert!(
            res.is_ok(),
            "Table '{}' query '{}' failed: {:?}",
            tbl,
            sql,
            res.err()
        );
    }
}

#[test]
fn test_challenge_complex_sql_operations() {
    let engine = SiqueryEngine::new();

    // 1. JOIN between processes and process_open_sockets
    let join_sql = "SELECT p.pid, p.name, s.local_port, s.state \
                    FROM processes p \
                    LEFT JOIN process_open_sockets s ON p.pid = s.pid \
                    LIMIT 10;";
    let join_res = engine.execute_query(join_sql).expect("LEFT JOIN must succeed");
    assert!(!join_res.is_empty(), "JOIN must return rows");

    // 2. GROUP BY and HAVING
    let group_sql = "SELECT name, count(*) as cnt FROM processes GROUP BY name HAVING cnt >= 1 ORDER BY cnt DESC LIMIT 5;";
    let group_res = engine.execute_query(group_sql).expect("GROUP BY must succeed");
    assert!(!group_res.is_empty(), "GROUP BY must return rows");

    // 3. Window functions
    let win_sql = "SELECT pid, name, DENSE_RANK() OVER (ORDER BY pid) as rnk FROM processes LIMIT 10;";
    let win_res = engine.execute_query(win_sql).expect("Window function must succeed");
    assert!(!win_res.is_empty(), "Window function must return rows");

    // 4. Subqueries
    let subquery_sql = "SELECT * FROM (SELECT pid, name, memory_rss_mb FROM processes WHERE pid > 0) sub WHERE sub.pid < 1000000 LIMIT 5;";
    let sub_res = engine.execute_query(subquery_sql).expect("Subquery must succeed");
    assert!(!sub_res.is_empty(), "Subquery must return rows");

    // 5. Output formatters
    let csv = engine.execute_csv(join_sql).expect("execute_csv must succeed");
    assert!(csv.contains("pid"));
    assert!(csv.contains("name"));
    assert!(csv.contains("local_port"));
    assert!(csv.contains("state"));

    let pretty = engine.execute_pretty(join_sql).expect("execute_pretty must succeed");
    assert!(pretty.contains("+---"));
    assert!(pretty.contains("| pid"));
}

#[test]
fn test_challenge_malformed_and_invalid_queries_graceful_recovery() {
    let engine = SiqueryEngine::new();

    // 1. Non-existent table
    let err1 = engine
        .execute_query("SELECT * FROM non_existent_virtual_table_98765;")
        .expect_err("Non-existent table must error");
    assert!(err1.contains("no such table"));

    // 2. Non-existent column
    let err2 = engine
        .execute_query("SELECT definitely_fake_column_xyz FROM processes;")
        .expect_err("Non-existent column must error");
    assert!(err2.contains("no such column"));

    // 3. Syntax error
    let err3 = engine
        .execute_query("SELECT FROM WHERE ;;;")
        .expect_err("Syntax error must return error");
    assert!(err3.contains("near") || err3.contains("syntax"));

    // 4. Unclosed string literal
    let err4 = engine
        .execute_query("SELECT 'unclosed string FROM processes;")
        .expect_err("Unclosed literal must return error");
    assert!(err4.contains("unrecognized token"));

    // 5. Division by zero
    let res5 = engine
        .execute_query("SELECT 1 / 0 AS res FROM processes LIMIT 1;")
        .expect("Division by zero in SQLite yields NULL, must not panic");
    assert_eq!(res5[0].get("res"), Some(&serde_json::Value::Null));
}

// ============================================================================
// 4. 12-SWEEP EDR AUDIT & KERNEL ANCHOR IMMUNITY
// ============================================================================

#[test]
fn test_challenge_12_sweep_edr_audit_and_kernel_anchor_immunity() {
    let engine = SiqueryEngine::new();

    // 1. Record an adversarial Incident A denial into GLOBAL_CORRELATOR
    let test_signal = DynamicDenialSignal {
        signal_id: format!("test-sig-{}", Utc::now().timestamp_micros()),
        session_id: "adversarial-test-session".to_string(),
        pid: 8888,
        parent_pid: Some(7777),
        command_line: "sudo -n apt-get update".to_string(),
        executable: "/usr/bin/sudo".to_string(),
        privilege_class: PrivilegeEquivalenceClass::RootOrAdminElevation,
        exit_code: Some(1),
        is_permission_denied: true,
        stderr_signature: Some("sudo: a password is required".to_string()),
        pattern_kind: DenialPatternKind::ExplicitRootAdminRequired,
        timestamp: Instant::now(),
        timestamp_utc: Utc::now().to_rfc3339(),
    };
    GLOBAL_CORRELATOR.record_denial(test_signal);

    // 2. Run active 12-sweep EDR audit
    let sweep = engine.run_siquery_edr_audit_sweep();
    assert_eq!(
        sweep.get("status").and_then(|v| v.as_str()),
        Some("ok"),
        "Sweep must succeed"
    );
    assert_eq!(
        sweep.get("sweeps_executed").and_then(|v| v.as_i64()),
        Some(12),
        "Must execute all 12 sweeps"
    );

    // Verify Sweep 12 flagged the circumvention anomaly
    let anomalies = sweep.get("anomalies").and_then(|v| v.as_array()).expect("Anomalies array");
    let has_circumvention = anomalies.iter().any(|a| {
        a.get("sweep").and_then(|v| v.as_str()) == Some("circumvention_events")
            && a.get("command_line").and_then(|v| v.as_str()) == Some("sudo -n apt-get update")
    });
    assert!(
        has_circumvention,
        "Sweep 12 must have detected the recorded permission denied circumvention signal"
    );

    // 3. KERNEL ANCHOR IMMUNITY ASSERTIONS:
    // Assert PID <= 4 and critical OS kernel anchors are strictly protected
    // and CANNOT be quarantined, frozen, or terminated under any host state.

    // A. Immutable PID range (PID 0, 1, 4, self)
    assert!(is_immutable_os_kernel_pid(0, "System Idle Process"));
    assert!(is_immutable_os_kernel_pid(1, "systemd"));
    assert!(is_immutable_os_kernel_pid(1, "init"));
    assert!(is_immutable_os_kernel_pid(4, "System"));
    assert!(is_immutable_os_kernel_pid(std::process::id(), "killswitch"));

    // B. Critical Windows Subsystem Kernel Anchors
    assert!(is_immutable_os_kernel_pid(1234, "csrss.exe"));
    assert!(is_immutable_os_kernel_pid(5678, "smss.exe"));
    assert!(is_immutable_os_kernel_pid(9999, "wininit.exe"));
    assert!(is_immutable_os_kernel_pid(8888, "services.exe"));
    assert!(is_immutable_os_kernel_pid(7777, "lsass.exe"));

    // C. Critical Linux Subsystem Kernel Anchors
    assert!(is_immutable_os_kernel_pid(1111, "systemd"));
    assert!(is_immutable_os_kernel_pid(2222, "systemd-journald"));
    assert!(is_immutable_os_kernel_pid(3333, "kthreadd"));

    // D. Developer Tools Are NOT Immune (Decoupled Immunity Law)
    assert!(!is_immutable_os_kernel_pid(99991, "wsl.exe"));
    assert!(!is_immutable_os_kernel_pid(99992, "node.exe"));
    assert!(!is_immutable_os_kernel_pid(99993, "python.exe"));
    assert!(!is_immutable_os_kernel_pid(99994, "cursor.exe"));
    assert!(!is_immutable_os_kernel_pid(99995, "code.exe"));
    assert!(!is_immutable_os_kernel_pid(99996, "bash"));
    assert!(!is_immutable_os_kernel_pid(99997, "sudo"));

    // E. NativeProcessFreezer Enforcement: Attempting to freeze PID <= 4 must fail closed!
    let freezer = NativeProcessFreezer::new();
    assert!(freezer.is_immutable_os_kernel(0, "System Idle Process"));
    assert!(freezer.is_immutable_os_kernel(4, "System"));
    assert!(freezer.is_immutable_os_kernel(1234, "csrss.exe"));

    // Freezing PID 4 MUST return Err(ContainmentViolation)
    let freeze_pid4 = freezer.freeze_process(4);
    assert!(
        freeze_pid4.is_err(),
        "Attempting to freeze PID 4 MUST fail closed and be rejected"
    );

    // Freezing csrss.exe (PID 0) MUST return Err(ContainmentViolation)
    let freeze_pid0 = freezer.freeze_process(0);
    assert!(
        freeze_pid0.is_err(),
        "Attempting to freeze PID 0 MUST fail closed and be rejected"
    );
}
