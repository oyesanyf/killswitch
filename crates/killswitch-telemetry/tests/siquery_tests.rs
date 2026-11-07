//! Integration tests for Siquery Relational SQL Discovery & Active EDR Engine (Milestone SEC-5).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use killswitch_core::exec_sensor::{simulate_exec_event, ExecEvent};
use killswitch_telemetry::agent_hooks::{
    evaluate_hook_synchronously, HookEventType, NormalizedHookRequest, SupportedAgentKind,
};
use killswitch_telemetry::siquery::{
    record_live_file_event, register_lineage_file_events_hook, register_lineage_open_files_hook,
    FileEventRecord, SiqueryEngine, LIVE_FILE_EVENTS,
};

#[test]
fn test_siquery_tables_list() {
    let tables = SiqueryEngine::list_tables();
    assert!(tables.len() >= 41, "Must expose at least 41 relational tables, found {}", tables.len());
    assert!(tables.contains(&"processes"));
    assert!(tables.contains(&"process_open_sockets"));
    assert!(tables.contains(&"coding_tools"));
    assert!(tables.contains(&"ide_extensions"));
    assert!(tables.contains(&"agent_interceptions"));
    assert!(tables.contains(&"exec_events"));
    assert!(tables.contains(&"circumvention_events"));
    assert!(tables.contains(&"dlp_semantic_events"));
    assert!(tables.contains(&"file_events"));
    assert!(tables.contains(&"live_file_events"));
    assert!(tables.contains(&"edr_threats"));
}

#[test]
fn test_siquery_processes_and_sockets_queries() {
    let engine = SiqueryEngine::new();

    // Query processes
    let proc_rows = engine
        .execute_query("SELECT pid, name, memory_rss_mb FROM processes LIMIT 5;")
        .expect("Should query processes");
    assert!(!proc_rows.is_empty(), "Processes table should return running processes");
    assert!(proc_rows[0].get("pid").is_some());
    assert!(proc_rows[0].get("name").is_some());

    // Query sockets
    let sock_rows = engine
        .execute_query("SELECT pid, local_port, remote_address, state FROM process_open_sockets LIMIT 5;")
        .expect("Should query sockets");
    assert!(!sock_rows.is_empty(), "Sockets table should return live sockets");

    // Test coding tools
    let tools = engine
        .execute_query("SELECT category, tool_name, version, pore_radius FROM coding_tools WHERE tool_name = 'cargo';")
        .expect("Should query coding tools");
    assert!(!tools.is_empty(), "Should discover cargo in coding_tools");
}

#[test]
fn test_siquery_telemetry_virtual_tables() {
    let engine = SiqueryEngine::new();

    // 1. Simulate an exec event
    simulate_exec_event(ExecEvent {
        pid: 99991,
        ppid: 99990,
        image_path: "C:\\Windows\\System32\\cmd.exe".to_string(),
        cmdline: "cmd.exe /c whoami".to_string(),
        timestamp_ns: 123456789,
        uid: Some(1000),
        euid: Some(1000),
        exit_code: Some(0),
    });

    let exec_rows = engine
        .execute_query("SELECT pid, ppid, cmdline FROM exec_events WHERE pid = 99991;")
        .expect("Should query exec_events");
    assert_eq!(exec_rows.len(), 1);
    assert_eq!(exec_rows[0].get("pid").unwrap().as_i64(), Some(99991));

    // 2. Simulate an agent interception event
    let req = NormalizedHookRequest {
        agent: SupportedAgentKind::Claude,
        event_type: HookEventType::PreToolUse,
        tool_name: Some("bash".to_string()),
        command: Some("git status".to_string()),
        file_path: None,
        arguments: None,
        exit_code: None,
        stderr: None,
        cwd: None,
        session_id: Some("test-session-sql".to_string()),
        rpc_id: None,
    };
    let _dec = evaluate_hook_synchronously(&req);

    let intercept_rows = engine
        .execute_query("SELECT event_id, agent_kind, tool_name, verdict FROM agent_interceptions WHERE command_line LIKE '%git status%';")
        .expect("Should query agent_interceptions");
    assert!(!intercept_rows.is_empty());
    assert_eq!(intercept_rows[0].get("agent_kind").unwrap().as_str(), Some("claude"));
    assert_eq!(intercept_rows[0].get("verdict").unwrap().as_str(), Some("ALLOW"));
}

#[test]
fn test_siquery_quadruple_read_only_guard() {
    let engine = SiqueryEngine::new();

    // Guard 1: Mutating statement prefixes must be rejected
    let mutating_queries = [
        "INSERT INTO processes (pid) VALUES (1);",
        "UPDATE processes SET pid = 2 WHERE pid = 1;",
        "DELETE FROM processes WHERE pid = 1;",
        "DROP TABLE file_events;",
        "ALTER TABLE processes ADD COLUMN fake TEXT;",
        "CREATE TABLE test (id INT);",
        "REPLACE INTO processes (pid) VALUES (1);",
        "TRUNCATE TABLE processes;",
        "ATTACH DATABASE 'leak.db' AS leak;",
        "DETACH DATABASE leak;",
    ];

    for q in &mutating_queries {
        let err = engine.execute_query(q).expect_err(&format!("Mutating query '{}' must be rejected", q));
        assert!(
            err.contains("Mutating SQL statements are forbidden (read-only query engine)"),
            "Error was: {}",
            err
        );
    }

    // SQL Injection Attempt: attempt stacked injection or trailing drop
    let injection_attempt = "SELECT * FROM processes; DROP TABLE file_events; --";
    // rusqlite prepare executes only the first statement, and authorizer forbids drop
    let _res = engine.execute_query(injection_attempt);
    // Verify file_events table still exists and queryable
    let check = engine.execute_query("SELECT COUNT(*) AS total FROM file_events;");
    assert!(check.is_ok(), "file_events table must not have been dropped");
}

#[test]
fn test_siquery_file_events_ring_buffer_flood_and_fifo() {
    // Flood ring buffer with 3,000 events to verify 1024 cap and FIFO order
    for i in 0..3000 {
        record_live_file_event(FileEventRecord {
            target_path: format!("C:\\temp\\test_{}.txt", i),
            action: "write".to_string(),
            pid: 1000 + (i as i64),
            process_name: "test.exe".to_string(),
            sha256: format!("hash_{:04}", i),
            time: 1700000000 + (i as i64),
        });
    }

    let guard = LIVE_FILE_EVENTS.read();
    assert_eq!(guard.len(), 1024, "LIVE_FILE_EVENTS must be strictly capped at 1024");
    // Verify FIFO: oldest remaining should be event 1976 (3000 - 1024)
    assert_eq!(guard.front().unwrap().target_path, "C:\\temp\\test_1976.txt");
    assert_eq!(guard.back().unwrap().target_path, "C:\\temp\\test_2999.txt");
    drop(guard);

    let engine = SiqueryEngine::new();
    let rows = engine
        .execute_query("SELECT COUNT(*) AS total FROM file_events;")
        .expect("Should query file_events");
    let total = rows[0].get("total").unwrap().as_i64().unwrap();
    assert!(total >= 1024);
}

#[test]
fn test_siquery_multithreaded_contention() {
    let engine = Arc::new(SiqueryEngine::new());
    let write_count = Arc::new(AtomicUsize::new(0));

    // 8 concurrent writers
    let mut handles = Vec::new();
    for thread_idx in 0..8 {
        let wc = write_count.clone();
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                record_live_file_event(FileEventRecord {
                    target_path: format!("C:\\data\\thread_{}_file_{}.dat", thread_idx, i),
                    action: "modify".to_string(),
                    pid: (thread_idx * 1000 + i) as i64,
                    process_name: "writer.exe".to_string(),
                    sha256: "aabbcc".to_string(),
                    time: 1700000000,
                });
                wc.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    // 4 concurrent readers
    for _ in 0..4 {
        let eng = engine.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..10 {
                let res = eng.execute_query("SELECT COUNT(*) AS total FROM file_events;");
                assert!(res.is_ok());
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(write_count.load(Ordering::SeqCst), 800);
}

#[test]
fn test_siquery_lineage_hooks_registration() {
    register_lineage_open_files_hook(|| {
        vec![
            (4242, 10, "C:\\confidential\\patient_records.pdf".to_string()),
            (4242, 11, "C:\\confidential\\keys.pem".to_string()),
        ]
    });

    register_lineage_file_events_hook(|| {
        vec![FileEventRecord {
            target_path: "C:\\confidential\\patient_records.pdf".to_string(),
            action: "read".to_string(),
            pid: 4242,
            process_name: "ai_agent.exe".to_string(),
            sha256: "deadbeef0011".to_string(),
            time: 1700000050,
        }]
    });

    let engine = SiqueryEngine::new();

    let open_files = engine
        .execute_query("SELECT pid, fd, path FROM open_files WHERE pid = 4242;")
        .expect("Should query open_files hook");
    assert_eq!(open_files.len(), 2);

    let events = engine
        .execute_query("SELECT target_path, pid, action FROM file_events WHERE pid = 4242;")
        .expect("Should query file_events hook");
    assert!(!events.is_empty());
    assert_eq!(events[0].get("action").unwrap().as_str(), Some("read"));
}

#[test]
fn test_siquery_formatters_json_csv_pretty() {
    let engine = SiqueryEngine::new();
    let sql = "SELECT 1 AS id, 'killswitch' AS name, 3.14 AS pi;";

    // 1. JSON
    let json = engine.execute_json(sql).expect("execute_json should succeed");
    assert!(json.contains("\"id\": 1"));
    assert!(json.contains("\"name\": \"killswitch\""));

    // 2. CSV (pipe-delimited)
    let csv = engine.execute_csv(sql).expect("execute_csv should succeed");
    assert!(csv.contains("id|name|pi"));
    assert!(csv.contains("1|killswitch|3.14"));

    // 3. Pretty box
    let pretty = engine.execute_pretty(sql).expect("execute_pretty should succeed");
    assert!(pretty.contains("+"));
    assert!(pretty.contains("| id"));
    assert!(pretty.contains("| name"));
    assert!(pretty.contains("| killswitch"));
}

#[test]
fn test_siquery_12_sweep_edr_audit() {
    let engine = SiqueryEngine::new();
    let report = engine.run_siquery_edr_audit_sweep();

    assert_eq!(report.get("status").and_then(|v| v.as_str()), Some("ok"));
    assert_eq!(report.get("sweeps_executed").and_then(|v| v.as_i64()), Some(12));
    assert!(report.get("execution_duration_ms").is_some());

    let metrics = report.get("metrics").expect("Must contain metrics");
    assert!(metrics.get("processes_count").is_some());
    assert!(metrics.get("sockets_count").is_some());
    assert!(metrics.get("services_count").is_some());

    let host = report.get("host").expect("Must contain host info");
    assert!(host.get("os").is_some());
    assert!(host.get("system").is_some());
    assert!(host.get("uptime").is_some());
}
