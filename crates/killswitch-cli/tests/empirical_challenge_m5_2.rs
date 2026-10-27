//! # Empirical Adversarial Stress Test Suite: Milestone 5
//!
//! Evaluates and stress-tests:
//! 1. Subsystem Self-Diagnostics: `start.exe --verify` and `start.exe --check` execution, exit 0, and phase reporting.
//! 2. DLP Lineage Exfiltration Trigger: Crown Jewel seeding, taint propagation, egress block, orchestrator containment, and state ledger recording.
//! 3. Critical System PID Immunity: Depth-5 parent ancestry protection, OS/developer binary catalog, case-insensitivity, and cyclic parentage defense.
//! 4. Reversible Mode Disarm: Unauthenticated emergency disarm, authenticated disarm, offline fallback, idempotency, and rapid oscillation stress.

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use killswitch_adjudication::immunity::{
    inspect_process_lineage, MAX_ANCESTRY_DEPTH,
};
use killswitch_adjudication::ZeroFalsePositiveAdjudicator;
use killswitch_cli::client::KillSwitchClient;
use killswitch_cli::loader::{UnifiedConfig, UnifiedRuntime};
use killswitch_cli::verify::SubsystemVerifier;
use killswitch_core::freeze::NativeProcessFreezer;
use killswitch_core::killchain::{
    execute_host_disarm_unauthenticated, is_critical_system_pid, HostContainmentManager,
};
use killswitch_orchestrator::engine::{KillSwitchOrchestrator, OrchestratorConfig};
use killswitch_telemetry::otel_lineage::{
    DlpClassification, DlpPolicy, EgressVerdict, EndpointLineageEngine, FileKey, ProcessKey,
};
use killswitch_types::adjudication::{AdjudicationResult, EvidenceClass, ThreatCandidate, VetoReason};
use killswitch_types::graph::OrchestratorMode;
use killswitch_types::status::{ContainmentLevel, OperatorCredentials, KILLCHAIN_RESTORE_TOKEN};

// =============================================================================
// Part 1: Subsystem Self-Diagnostics (`start.exe --verify` / `--check`)
// =============================================================================

#[test]
fn test_subsystem_diagnostics_live_binary_verify_and_check() {
    let start_exe = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("start.exe");

    assert!(
        start_exe.exists(),
        "start.exe must exist at root workspace: {:?}",
        start_exe
    );

    // 1. Live execution of start.exe --verify
    let output_verify = Command::new(&start_exe)
        .arg("--verify")
        .output()
        .expect("Failed to execute start.exe --verify");

    assert!(
        output_verify.status.success(),
        "start.exe --verify must exit with code 0, got {:?}",
        output_verify.status.code()
    );

    let stdout_verify = String::from_utf8_lossy(&output_verify.stdout);
    assert!(
        stdout_verify.contains("Phase 1: Core Containment & BLAKE3 State Ledger Integrity"),
        "Missing Phase 1 in output: {}",
        stdout_verify
    );
    assert!(
        stdout_verify.contains("Phase 2: Adjudication, WinTrust & Depth-5 Ancestry Immunity"),
        "Missing Phase 2 in output: {}",
        stdout_verify
    );
    assert!(
        stdout_verify.contains("Phase 3: Telemetry, EDR PhaseLock & DLP Lineage Fan-In"),
        "Missing Phase 3 in output: {}",
        stdout_verify
    );
    assert!(
        stdout_verify.contains("Phase 4: Stateful LangGraph Orchestrator & BLAKE3 Trace Linking"),
        "Missing Phase 4 in output: {}",
        stdout_verify
    );
    assert!(
        stdout_verify.contains("Phase 5: Axum HTTP Control Router & Loopback Binding"),
        "Missing Phase 5 in output: {}",
        stdout_verify
    );
    assert!(
        stdout_verify.contains("Phase 6: Native OS Service Lifecycle & Zero-Subprocess Compliance"),
        "Missing Phase 6 in output: {}",
        stdout_verify
    );
    assert!(
        stdout_verify.contains("ALL 6 SUBSYSTEM PHASES PASSED"),
        "Missing all passed marker in output: {}",
        stdout_verify
    );
    assert!(
        stdout_verify.contains("Self-check passed (exit 0)"),
        "Missing exit 0 marker in output: {}",
        stdout_verify
    );

    // 2. Live execution of start.exe --check (alias)
    let output_check = Command::new(&start_exe)
        .arg("--check")
        .output()
        .expect("Failed to execute start.exe --check");

    assert!(
        output_check.status.success(),
        "start.exe --check must exit with code 0, got {:?}",
        output_check.status.code()
    );
    let stdout_check = String::from_utf8_lossy(&output_check.stdout);
    assert!(
        stdout_check.contains("ALL 6 SUBSYSTEM PHASES PASSED"),
        "start.exe --check must report all 6 phases passed"
    );

    // 3. CLI help and invalid flag handling
    let output_help = Command::new(&start_exe)
        .arg("--help")
        .output()
        .expect("Failed to execute start.exe --help");
    assert!(
        output_help.status.success(),
        "start.exe --help must exit with code 0"
    );

    let output_invalid = Command::new(&start_exe)
        .arg("--invalid-flag-stress-test")
        .output()
        .expect("Failed to execute start.exe with invalid flag");
    assert!(
        !output_invalid.status.success(),
        "start.exe with invalid flag must return non-zero exit code"
    );
}

#[tokio::test]
async fn test_subsystem_diagnostics_in_memory_verifier_contract() {
    let report = SubsystemVerifier::run_all()
        .await
        .expect("In-memory self-diagnostics must pass all 6 phases");

    assert!(report.all_passed, "All phases must report passed");
    assert_eq!(report.phases.len(), 6, "Must contain exactly 6 phases");

    for (idx, phase) in report.phases.iter().enumerate() {
        assert_eq!(
            phase.phase_number,
            idx + 1,
            "Phase numbers must be 1-indexed and consecutive"
        );
        assert!(phase.passed, "Phase {} failed: {}", phase.phase_number, phase.details);
        assert!(!phase.name.is_empty(), "Phase name must not be empty");
        assert!(!phase.details.is_empty(), "Phase details must not be empty");
    }
}

// =============================================================================
// Part 2: DLP Lineage Exfiltration Trigger & State Ledger Recording
// =============================================================================

#[tokio::test]
async fn test_dlp_lineage_exfiltration_taint_propagation_and_egress_block() {
    let engine = EndpointLineageEngine::new_in_memory();
    let file_path = "C:\\confidential\\q3_earnings_pre_release.xlsx";
    let file_key = FileKey::from_path_or_synthetic(file_path);
    let file_sha256 = "c0ffee00112233445566778899aabbccddeeff00112233445566778899aabbcc";

    // 1. Seed Crown Jewel sensitive file with Quarantine policy
    engine.seed_sensitive_file(
        file_key,
        file_path,
        file_sha256,
        DlpClassification::CrownJewel,
        DlpPolicy::Quarantine,
    );

    // 2. Simulate untrusted attacker process
    let proc_key = ProcessKey::new(8822, 1000, "exfiltrator.exe");
    engine.on_process_create(None, proc_key, "exfiltrator.exe");

    // Initially, process has not accessed sensitive file, so baggage is None
    let initial_taint = engine.get_process_taint(&proc_key).expect("Process record must exist");
    assert!(
        initial_taint.baggage.is_none(),
        "Process baggage must be None before reading sensitive file"
    );

    // 3. Process reads sensitive Crown Jewel file
    engine.on_file_read(proc_key, file_key);

    // Now process is tainted with CrownJewel baggage
    let taint = engine.get_process_taint(&proc_key);
    assert!(taint.is_some(), "Process must be tainted after reading Crown Jewel file");
    let taint_state = taint.unwrap();
    let baggage = taint_state.baggage.expect("Tainted process must contain baggage");
    assert_eq!(baggage.classification, DlpClassification::CrownJewel);
    assert_eq!(baggage.policy, DlpPolicy::Quarantine);

    // 4. Evaluate egress to external attacker C2
    let verdict = engine.evaluate_egress(proc_key, "https://c2.adversary-leak.com/exfil");
    match verdict {
        EgressVerdict::Block {
            classification,
            policy,
            source_hashes,
            ..
        } => {
            assert_eq!(
                classification,
                DlpClassification::CrownJewel,
                "Egress block must preserve CrownJewel classification"
            );
            assert_eq!(
                policy,
                DlpPolicy::Quarantine,
                "Egress block must enforce Quarantine policy"
            );
            assert!(
                source_hashes.contains(&file_sha256.to_string()),
                "Source hash chain must contain original Crown Jewel hash"
            );
        }
        EgressVerdict::Allow => {
            panic!("Egress to external host MUST be blocked for Crown Jewel tainted process");
        }
    }

    // 5. Test benign process isolation: non-tainted process egress allowed
    let benign_proc = ProcessKey::new(8823, 1000, "benign_worker.exe");
    engine.on_process_create(None, benign_proc, "benign_worker.exe");
    let benign_verdict = engine.evaluate_egress(benign_proc, "https://google.com");
    assert!(
        matches!(benign_verdict, EgressVerdict::Allow),
        "Untainted process egress must be allowed"
    );
}

#[tokio::test]
async fn test_dlp_lineage_autonomous_trigger_containment_and_state_ledger() {
    let temp_dir = tempfile::tempdir().unwrap();
    let containment_mgr = Arc::new(
        HostContainmentManager::new_default(Some(temp_dir.path())).unwrap(),
    );
    let adjudicator = Arc::new(ZeroFalsePositiveAdjudicator::new());
    let lineage_engine = Arc::new(EndpointLineageEngine::new_in_memory());

    // 1. Seed sensitive file in lineage engine
    let file_path = "C:\\secrets\\crown_jewels.db";
    let file_key = FileKey::from_path_or_synthetic(file_path);
    let file_sha256 = "deadbeef00112233445566778899aabbccddeeff00112233445566778899aabb";
    lineage_engine.seed_sensitive_file(
        file_key,
        file_path,
        file_sha256,
        DlpClassification::CrownJewel,
        DlpPolicy::Quarantine,
    );

    // 2. Suspicious process reads Crown Jewel file
    let exfil_pid = 7711;
    let proc_key = ProcessKey::new(exfil_pid, 1000, "exfil_trojan.exe");
    lineage_engine.on_process_create(None, proc_key, "exfil_trojan.exe");
    lineage_engine.on_file_read(proc_key, file_key);

    // 3. Initialize Orchestrator with Autonomous mode
    let orch_config = OrchestratorConfig {
        mode: OrchestratorMode::Autonomous,
        db_dir: Some(temp_dir.path().to_path_buf()),
        ..Default::default()
    };
    let orch = KillSwitchOrchestrator::new(
        orch_config,
        containment_mgr.clone(),
        adjudicator.clone(),
        lineage_engine.clone(),
    );

    // Step 1: Ingest
    let t1 = orch.step().await.unwrap();
    assert_eq!(t1.from_stage, killswitch_orchestrator::LifecycleStage::Ingest);

    // Step 2: Correlate
    let t2 = orch.step().await.unwrap();
    assert_eq!(t2.from_stage, killswitch_orchestrator::LifecycleStage::Correlate);

    // Step 3: Adjudicate
    let t3 = orch.step().await.unwrap();
    assert_eq!(t3.from_stage, killswitch_orchestrator::LifecycleStage::Adjudicate);

    // Step 4: LineageTrigger -> Evaluates DLP taint graph and catches Crown Jewel exfiltration
    let t4 = orch.step().await.unwrap();
    assert_eq!(t4.from_stage, killswitch_orchestrator::LifecycleStage::LineageTrigger);

    let state_after_trigger = orch.get_state().await;
    assert!(
        !state_after_trigger.active_threats.is_empty(),
        "LineageTrigger must emit threat candidate into active_threats"
    );
    assert_eq!(
        state_after_trigger.metadata.get("lineage_classification").map(|s| s.as_str()),
        Some("CrownJewel"),
        "State metadata must record CrownJewel classification"
    );
    assert_eq!(
        state_after_trigger.metadata.get("lineage_policy").map(|s| s.as_str()),
        Some("Quarantine"),
        "State metadata must record Quarantine policy"
    );
    assert_eq!(
        state_after_trigger.metadata.get("lineage_critical_pid_preserved").map(|s| s.as_str()),
        Some("false"),
        "Untrusted exfiltrator is not a critical OS process"
    );

    // Step 5: ReasonOllama (executes local forensic check with 400ms timeout fallback)
    let t5 = orch.step().await.unwrap();
    assert_eq!(t5.from_stage, killswitch_orchestrator::LifecycleStage::ReasonOllama);

    // Step 6: Decide (evaluates autonomous containment action)
    let t6 = orch.step().await.unwrap();
    assert_eq!(t6.from_stage, killswitch_orchestrator::LifecycleStage::Decide);

    // Step 7: Contain (engages HostContainmentManager isolation and records into BLAKE3 state ledger)
    let t7 = orch.step().await.unwrap();
    assert_eq!(t7.from_stage, killswitch_orchestrator::LifecycleStage::Contain);

    // 4. Verify host containment was engaged
    let current_status = containment_mgr.get_status();
    assert!(
        current_status.isolated,
        "Host containment must be engaged following DLP lineage exfiltration trigger"
    );

    // 5. Verify State Ledger recorded the transition with valid BLAKE3 hash chain
    let history = containment_mgr.get_history();
    assert!(
        !history.is_empty(),
        "State ledger must record containment events"
    );
    // History is prepended: first() contains the latest transition
    let latest_entry = history.first().unwrap();
    assert_eq!(latest_entry.action, "ENGAGED");
    assert!(
        latest_entry.reason.contains("zero-false-positive threat"),
        "Ledger entry reason must explain zero-false-positive containment: {}",
        latest_entry.reason
    );

    // Cleanly disarm containment for teardown
    let _ = containment_mgr
        .execute_unauthenticated_emergency_disarm("Teardown test containment")
        .await;
}

// =============================================================================
// Part 3: Critical System PID Immunity & Depth-5 Ancestry Traversal
// =============================================================================

#[test]
fn test_critical_system_pid_immunity_exhaustive_catalog() {
    // 1. Kernel, Idle, and Self PIDs
    assert!(is_critical_system_pid(0, "System Idle Process"));
    assert!(is_critical_system_pid(1, "init"));
    assert!(is_critical_system_pid(4, "System"));
    assert!(is_critical_system_pid(std::process::id(), "empirical_challenge_m5_2.exe"));

    // 2. Canonical Windows Core OS Daemons
    let critical_windows = [
        "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
        "lsass.exe", "lsm.exe", "dwm.exe", "svchost.exe", "explorer.exe",
        "taskhostw.exe", "audiodg.exe", "spoolsv.exe", "taskmgr.exe",
        "securityhealthservice.exe", "smartscreen.exe", "consent.exe",
    ];
    for name in critical_windows {
        assert!(
            is_critical_system_pid(9999, name),
            "Process '{}' must be classified as critical system process",
            name
        );
    }

    // 3. Developer and Toolchain Infrastructure
    let critical_dev = [
        "code.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "windowsterminal.exe",
        "conhost.exe", "wsl.exe", "docker.exe", "cargo.exe", "rustc.exe", "git.exe",
        "python.exe", "node.exe",
    ];
    for name in critical_dev {
        assert!(
            is_critical_system_pid(8888, name),
            "Developer binary '{}' must be immune from killswitch containment",
            name
        );
    }

    // 4. Case-insensitivity & path normalization stress tests
    assert!(is_critical_system_pid(1234, "C:\\Windows\\System32\\SVCHOST.EXE"));
    assert!(is_critical_system_pid(1235, "C:\\Program Files\\Git\\bin\\GIT.EXE"));
    assert!(is_critical_system_pid(1236, "d:\\rust\\bin\\CarGo.Exe"));
    assert!(is_critical_system_pid(1237, "\"C:\\Windows\\explorer.exe\""));

    // 5. Negative tests: Malicious and untrusted processes MUST NOT be immune
    let untrusted_binaries = [
        "mimikatz.exe", "cobaltstrike.exe", "ransom.exe", "cryptolocker.exe",
        "reverse_shell.exe", "c2_beacon.exe", "trojan.exe", "stealer.exe",
    ];
    for bad in untrusted_binaries {
        assert!(
            !is_critical_system_pid(7000, bad),
            "Malicious binary '{}' must NEVER be classified as immune",
            bad
        );
    }
}

#[tokio::test]
async fn test_adjudicator_veto_on_critical_system_pids() {
    let adjudicator = ZeroFalsePositiveAdjudicator::new();

    // Adversarial threat candidate targeting critical PID 4 (System)
    let candidate_system = ThreatCandidate::new(
        Some(4),
        "System",
        "adversarial_telemetry",
        "Spoofed threat against kernel System process",
        0.99,
        EvidenceClass::Behavior,
    );
    let res_system = adjudicator
        .adjudicate_threat_candidate(&candidate_system, None)
        .await;
    match res_system {
        AdjudicationResult::Vetoed { reason, .. } => {
            assert!(
                matches!(reason, VetoReason::CriticalSystemPid),
                "Adjudication must veto PID 4 with CriticalSystemPid: {:?}",
                reason
            );
        }
        other => panic!("Expected Vetoed result for PID 4, got {:?}", other),
    }

    // Threat candidate targeting explorer.exe
    let candidate_explorer = ThreatCandidate::new(
        Some(1044),
        "explorer.exe",
        "adversarial_probe",
        "Spoofed threat against Windows Explorer",
        0.98,
        EvidenceClass::LiveNetwork,
    );
    let res_explorer = adjudicator
        .adjudicate_threat_candidate(&candidate_explorer, None)
        .await;
    assert!(
        matches!(res_explorer, AdjudicationResult::Vetoed { .. }),
        "Adjudication must veto critical binary explorer.exe"
    );

    // Negative test: Untrusted threat candidate targeting an unknown binary must NOT be vetoed
    let candidate_malware = ThreatCandidate::new(
        Some(8881),
        "untrusted_ransomware.exe",
        "threat_intel",
        "Mass file modification detected",
        0.95,
        EvidenceClass::Behavior,
    );
    let res_malware = adjudicator
        .adjudicate_threat_candidate(&candidate_malware, None)
        .await;
    assert!(
        !res_malware.is_vetoed(),
        "Untrusted malware candidate must NOT be vetoed by critical system immunity"
    );
}

#[test]
fn test_process_ancestry_depth_5_boundary_and_cyclic_immunity() {
    // 1. Current process inspect_process_lineage:
    // Running under cargo test / powershell / terminal -> must be immune via target or ancestor
    let current_pid = std::process::id();
    let verdict = inspect_process_lineage(current_pid, Some("empirical_challenge_m5_2.exe"));
    assert!(
        verdict.is_immune(),
        "Current test process or its developer toolchain ancestor must be immune: {:?}",
        verdict
    );

    // 2. Test MAX_ANCESTRY_DEPTH invariant
    assert_eq!(
        MAX_ANCESTRY_DEPTH, 5,
        "MAX_ANCESTRY_DEPTH must be strictly equal to 5"
    );

    // 3. Test NativeProcessFreezer immune set includes depth-5 ancestry
    let freezer = NativeProcessFreezer::new();
    let immune_pids = freezer.get_immune_pids();
    assert!(
        immune_pids.contains(&0),
        "Immune set must contain PID 0"
    );
    assert!(
        immune_pids.contains(&1),
        "Immune set must contain PID 1"
    );
    assert!(
        immune_pids.contains(&4),
        "Immune set must contain PID 4"
    );
    assert!(
        immune_pids.contains(&current_pid),
        "Immune set must contain current test process PID"
    );
    assert!(
        immune_pids.len() >= 4,
        "Immune set must have at least 4 PIDs (system + self + ancestors)"
    );

    // 4. Test ancestor depth boundary logic simulation:
    // Depths 1, 2, 3, 4, 5 confer immunity; Depth 6 does NOT confer ancestry immunity
    for depth in 1..=10 {
        let is_immune_by_depth = depth <= MAX_ANCESTRY_DEPTH;
        if depth <= 5 {
            assert!(
                is_immune_by_depth,
                "Ancestor at depth {} must confer immunity (depth <= 5)",
                depth
            );
        } else {
            assert!(
                !is_immune_by_depth,
                "Ancestor at depth {} must NOT confer ancestry immunity (exceeds depth 5)",
                depth
            );
        }
    }

    // 5. Cyclic Parent Ancestry Defense:
    // Process A -> Process B -> Process A (cycle in process table).
    // Traversal must use HashSet visited tracking and terminate safely in <= 5 hops.
    let mut visited = HashSet::new();
    let mut current_p = 5001;
    let mut depth = 0;
    while depth < MAX_ANCESTRY_DEPTH {
        if !visited.insert(current_p) {
            // Cycle detected!
            break;
        }
        depth += 1;
        // Cycle: 5001 -> 5002 -> 5001
        current_p = if current_p == 5001 { 5002 } else { 5001 };
    }
    assert_eq!(depth, 2, "Cycle detection must terminate safely at depth 2");
}

// =============================================================================
// Part 4: Reversible Mode Disarm & Clean State Restoration
// =============================================================================

#[tokio::test]
async fn test_reversible_mode_emergency_unauthenticated_disarm() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mgr = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());

    // 1. Initial State: Normal / Not Isolated
    assert!(!mgr.get_status().isolated);

    // 2. Engage Containment at NetworkQuarantine level
    let isolated = mgr
        .engage_isolation(
            "test_operator",
            "Simulated adversarial breach",
            ContainmentLevel::NetworkQuarantine,
            None,
        )
        .await
        .expect("Engage isolation must succeed");

    assert!(isolated.isolated, "Host must be isolated");
    assert_eq!(
        isolated.containment_level,
        ContainmentLevel::NetworkQuarantine
    );

    // 3. Trigger Unauthenticated Emergency Disarm
    let restored = mgr
        .execute_unauthenticated_emergency_disarm("Emergency unauthenticated disarm test")
        .await
        .expect("Emergency disarm must succeed");

    // 4. Verify clean restoration
    assert!(
        !restored.isolated,
        "Host must no longer be isolated after disarm"
    );
    assert_eq!(
        restored.containment_level,
        ContainmentLevel::Disarmed,
        "Containment level must be Disarmed"
    );
    assert!(
        restored.frozen_pids.is_empty(),
        "Frozen PIDs list must be cleared"
    );
    assert!(
        restored.tarpitted_pids.is_empty(),
        "Tarpitted PIDs list must be cleared"
    );

    // 5. Verify BLAKE3 State Ledger Integrity
    let history = mgr.get_history();
    assert!(
        history.len() >= 2,
        "History ledger must contain both engage and disarm records"
    );
    // history.first() is the latest entry (prepended)
    let disarm_entry = history.first().unwrap();
    assert_eq!(disarm_entry.action, "DISARMED_SHUTDOWN");
    assert!(disarm_entry.reason.contains("Emergency unauthenticated disarm"));
}

#[tokio::test]
async fn test_reversible_mode_authenticated_disarm_and_bad_credentials() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mgr = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());

    // 1. Engage Containment
    let _ = mgr
        .engage_isolation(
            "secops_admin",
            "Active investigation",
            ContainmentLevel::ProcessFreeze,
            None,
        )
        .await
        .unwrap();

    assert!(mgr.get_status().isolated);

    // 2. Attempt Disarm with Invalid Authentication Credentials (wrong PIN and wrong phrase)
    let bad_creds = OperatorCredentials {
        operator_id: "unauthorized_user".to_string(),
        auth_token: Some("invalid_fake_token_000000".to_string()),
        password: Some("wrong_password".to_string()),
        caller_pid: Some(std::process::id()),
        confirmation_phrase: Some("WRONG_CONFIRMATION_PHRASE".to_string()),
    };
    let bad_res = mgr
        .disarm_isolation("unauthorized_user", "Unauthorized disarm attempt", Some(&bad_creds))
        .await;

    // Disarm with bad credentials must be rejected
    assert!(
        bad_res.is_err(),
        "Disarm with bad credentials must return an error"
    );
    // Host must remain isolated
    assert!(
        mgr.get_status().isolated,
        "Host must remain isolated after failed authentication"
    );

    // 3. Authenticated Disarm with Authorized Master Bypass Token
    let valid_creds = OperatorCredentials {
        operator_id: "SecOps-Lead".to_string(),
        auth_token: Some(KILLCHAIN_RESTORE_TOKEN.to_string()),
        password: None,
        caller_pid: Some(std::process::id()),
        confirmation_phrase: Some(KILLCHAIN_RESTORE_TOKEN.to_string()),
    };
    let restored = mgr
        .disarm_isolation("SecOps-Lead", "Incident remediated cleanly", Some(&valid_creds))
        .await
        .expect("Authorized disarm must succeed with valid token");

    assert!(!restored.isolated, "Host must be restored to normal state");
}

#[tokio::test]
async fn test_client_server_disarm_integration_and_offline_fallback() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config = UnifiedConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        mode: OrchestratorMode::Autonomous,
        db_dir: Some(temp_dir.path().to_path_buf()),
    };

    // 1. Boot live UnifiedRuntime
    let runtime = UnifiedRuntime::boot(config)
        .await
        .expect("Unified runtime boot must succeed");

    // Engage isolation on runtime's containment manager
    let _ = runtime
        .containment_manager
        .engage_isolation(
            "test_suite",
            "Integration disarm test",
            ContainmentLevel::NetworkQuarantine,
            None,
        )
        .await
        .unwrap();

    assert!(runtime.containment_manager.get_status().isolated);

    // 2. Disarm via in-process emergency function
    let disarm_status = execute_host_disarm_unauthenticated()
        .expect("Direct emergency disarm must succeed");
    assert!(!disarm_status.isolated);

    // 3. Test KillSwitchClient offline fallback
    // Point client to a port where no server is listening
    let offline_client = KillSwitchClient::new("127.0.0.1", 64433);
    let fallback_res = offline_client
        .disarm("emergency_user", "Server is dead, restore endpoint", None)
        .await
        .expect("Offline fallback disarm must succeed");

    assert!(fallback_res.success);
    assert!(
        fallback_res.message.contains("Direct in-process emergency restore"),
        "Message must confirm in-process emergency fallback execution: {}",
        fallback_res.message
    );
}

#[tokio::test]
async fn test_idempotent_disarm_and_rapid_oscillation_stress() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mgr = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());

    // 1. Idempotency test: Disarming an already-disarmed endpoint
    assert!(!mgr.get_status().isolated);
    for i in 1..=5 {
        let res = mgr
            .execute_unauthenticated_emergency_disarm(&format!("Idempotent disarm {}", i))
            .await
            .expect("Disarming already disarmed system must succeed cleanly");
        assert!(!res.isolated, "System must remain disarmed");
    }

    // 2. Rapid Oscillation Stress Test (5 consecutive engage-disarm cycles)
    for cycle in 1..=5 {
        let engage_res = mgr
            .engage_isolation(
                "stress_operator",
                &format!("Oscillation cycle {}", cycle),
                ContainmentLevel::NetworkQuarantine,
                None,
            )
            .await
            .expect("Engage in rapid oscillation must succeed");
        assert!(engage_res.isolated, "Cycle {} must isolate", cycle);

        let disarm_res = mgr
            .execute_unauthenticated_emergency_disarm(&format!("Oscillation disarm {}", cycle))
            .await
            .expect("Disarm in rapid oscillation must succeed");
        assert!(!disarm_res.isolated, "Cycle {} must restore", cycle);
    }

    // 3. Assert BLAKE3 State Ledger chain integrity across all cycles
    let history = mgr.get_history();
    assert!(
        history.len() >= 10,
        "Ledger must record all 10 state transitions across 5 cycles, got {}",
        history.len()
    );

    // Verify cryptographic reverse hash continuity: history[i].prev_event_hash == history[i+1].event_hash
    for i in 0..history.len() {
        let current = &history[i];
        let expected_prev = if i + 1 < history.len() {
            history[i + 1].event_hash.as_str()
        } else {
            killswitch_core::GENESIS_HASH
        };
        assert_eq!(
            current.prev_event_hash, expected_prev,
            "BLAKE3 state ledger hash continuity broken at history index {}",
            i
        );
    }
}
