//! Integration and invariant tests for `killswitch-orchestrator`.

use std::sync::Arc;
use killswitch_adjudication::ZeroFalsePositiveAdjudicator;
use killswitch_core::killchain::HostContainmentManager;
use killswitch_orchestrator::checkpointer::DurableFileCheckpointer;
use killswitch_orchestrator::ollama::OllamaReasoningEngine;
use killswitch_orchestrator::state::LifecycleStage;
use killswitch_orchestrator::{KillSwitchOrchestrator, OrchestratorConfig};
use killswitch_telemetry::otel_lineage::{
    DlpClassification, DlpPolicy, EndpointLineageEngine, FileKey, ProcessKey,
};
use killswitch_types::adjudication::ThreatCandidate;
use killswitch_types::errors::KillSwitchError;
use killswitch_types::graph::{
    ApprovalDecision, GraphNodeId, KillSwitchGraphState, OperatorApprovalState,
    OrchestratorMode, StateCheckpointer,
};


#[test]
fn test_dynamic_available_memory_law() {
    let m48 = OllamaReasoningEngine::select_model_from_free_ram_gb(50.0);
    assert_eq!(m48, "qwen2.5:32b");
    assert!(!m48.contains("-coder"));

    let m24 = OllamaReasoningEngine::select_model_from_free_ram_gb(30.0);
    assert_eq!(m24, "qwen2.5:14b");
    assert!(!m24.contains("-coder"));

    let m12 = OllamaReasoningEngine::select_model_from_free_ram_gb(16.0);
    assert_eq!(m12, "qwen2.5:7b");
    assert!(!m12.contains("-coder"));

    let m6 = OllamaReasoningEngine::select_model_from_free_ram_gb(8.0);
    assert_eq!(m6, "qwen2.5:3b");
    assert!(!m6.contains("-coder"));

    let m_low = OllamaReasoningEngine::select_model_from_free_ram_gb(3.5);
    assert_eq!(m_low, "qwen2.5:1.5b");
    assert!(!m_low.contains("-coder"));
}

#[tokio::test]
async fn test_ollama_400ms_timeout_fallback() {
    // Port 59999 is inactive; probe must timeout within 400ms and return fallback
    let engine = OllamaReasoningEngine::new("http://127.0.0.1:59999");
    let start = std::time::Instant::now();
    let res = engine.evaluate_forensics("Test threat analysis").await;
    let elapsed = start.elapsed();

    assert!(res.is_offline_fallback);
    assert_eq!(res.forensic_verdict, "CONFIRM_CONTAINMENT");
    assert!(res.confidence >= 0.90);
    // Timeout deadline is 400ms, should complete in ~400-800ms
    assert!(elapsed.as_millis() < 1500, "Ollama probe exceeded allowable timeout threshold: {:?}ms", elapsed.as_millis());
}


#[test]
fn test_blake3_trace_chain_integrity_and_tamper_detection() {
    let mut state = KillSwitchGraphState::new("inc-trace-001", OrchestratorMode::Autonomous);

    // Record 3 steps
    state.record_execution_step(
        GraphNodeId::IngestingSignals,
        "input_hash_1",
        "output_hash_1",
        10,
        serde_json::json!({"action": "ingest"}),
    );
    state.record_execution_step(
        GraphNodeId::CorrelatingEdrAndOctopus,
        "input_hash_2",
        "output_hash_2",
        15,
        serde_json::json!({"action": "correlate"}),
    );
    state.record_execution_step(
        GraphNodeId::AdjudicatingZeroFalsePositive,
        "input_hash_3",
        "output_hash_3",
        20,
        serde_json::json!({"action": "adjudicate"}),
    );

    assert_eq!(state.execution_trace.len(), 3);
    assert!(state.verify_trace_chain());

    // Tamper with step 1's input digest
    state.execution_trace[1].input_digest = "tampered_digest".to_string();
    assert!(!state.verify_trace_chain(), "Trace chain must fail verification when step is tampered");
}

#[tokio::test]
async fn test_durable_checkpointer_atomic_save_load() {
    let temp_dir = tempfile::tempdir().unwrap();
    let checkpointer = DurableFileCheckpointer::new(temp_dir.path()).unwrap();

    let mut state = KillSwitchGraphState::new("inc-chk-001", OrchestratorMode::Autonomous);
    state.record_execution_step(
        GraphNodeId::IngestingSignals,
        "in_1",
        "out_1",
        5,
        serde_json::json!({"status": "ok"}),
    );

    checkpointer.save_checkpoint(&state).await.unwrap();

    let loaded = checkpointer.load_checkpoint("inc-chk-001").await.unwrap();
    assert!(loaded.is_some());
    let loaded_state = loaded.unwrap();
    assert_eq!(loaded_state.incident_id, "inc-chk-001");
    assert!(loaded_state.verify_trace_chain());
}

#[tokio::test]
async fn test_checkpointer_corruption_fails_closed() {
    let temp_dir = tempfile::tempdir().unwrap();
    let checkpointer = DurableFileCheckpointer::new(temp_dir.path()).unwrap();

    let mut state = KillSwitchGraphState::new("inc-corrupt-001", OrchestratorMode::Autonomous);
    state.record_execution_step(
        GraphNodeId::IngestingSignals,
        "in_1",
        "out_1",
        5,
        serde_json::json!({"status": "ok"}),
    );

    checkpointer.save_checkpoint(&state).await.unwrap();

    // Corrupt the checkpoint file by modifying JSON to have bad chain_hash
    let path = temp_dir.path().join("checkpoint_inc-corrupt-001.json");
    let content = std::fs::read_to_string(&path).unwrap();
    let tampered = content.replace("out_1", "tampered_out");
    std::fs::write(&path, tampered).unwrap();

    let res = checkpointer.load_checkpoint("inc-corrupt-001").await;
    assert!(res.is_err());
    match res.unwrap_err() {
        KillSwitchError::CryptoError(msg) => {
            assert!(msg.contains("BLAKE3 execution trace chain verification failed"));
        }
        other => panic!("Expected CryptoError, got {:?}", other),
    }
}

#[tokio::test]
async fn test_autonomous_dlp_lineage_trigger_in_orchestrator() {
    let temp_dir = tempfile::tempdir().unwrap();
    let lineage = Arc::new(EndpointLineageEngine::new_in_memory());
    let adjudicator = Arc::new(ZeroFalsePositiveAdjudicator::new());
    let containment = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());

    let config = OrchestratorConfig {
        mode: OrchestratorMode::Autonomous,
        db_dir: Some(temp_dir.path().to_path_buf()),
        consecutive_healthy_probes_required: 3,
        probe_interval_secs: 60,
        watchdog_max_secs: 1800,
    };

    let orch = KillSwitchOrchestrator::new(config, containment, adjudicator, lineage.clone());

    // Seed DLP sensitive file
    let file_key = FileKey::from_path_or_synthetic("C:\\vault\\crown_secret.docx");
    lineage.seed_sensitive_file(
        file_key,
        "C:\\vault\\crown_secret.docx",
        "sha256_crown_1234",
        DlpClassification::CrownJewel,
        DlpPolicy::Quarantine,
    );

    // Process reads file
    let proc_key = ProcessKey::new(7120, 1000, "bad_exfil.exe");
    lineage.on_process_create(None, proc_key, "bad_exfil.exe");
    lineage.on_file_read(proc_key, file_key);

    // Step through orchestrator
    // 1. Ingest
    let t1 = orch.step().await.unwrap();
    assert_eq!(t1.from_stage, LifecycleStage::Ingest);

    // 2. Correlate
    let t2 = orch.step().await.unwrap();
    assert_eq!(t2.from_stage, LifecycleStage::Correlate);

    // 3. Adjudicate
    let t3 = orch.step().await.unwrap();
    assert_eq!(t3.from_stage, LifecycleStage::Adjudicate);

    // 4. LineageTrigger: should catch the CrownJewel + Quarantine exfiltration
    let t4 = orch.step().await.unwrap();
    assert_eq!(t4.from_stage, LifecycleStage::LineageTrigger);

    let state = orch.get_state().await;
    assert!(!state.active_threats.is_empty(), "DLP trigger must identify threat candidate");
    assert_eq!(state.metadata.get("lineage_classification").unwrap(), "CrownJewel");
    assert_eq!(state.metadata.get("lineage_policy").unwrap(), "Quarantine");
}

#[tokio::test]
async fn test_manual_mode_pause_and_operator_approval() {
    let temp_dir = tempfile::tempdir().unwrap();
    let lineage = Arc::new(EndpointLineageEngine::new_in_memory());
    let adjudicator = Arc::new(ZeroFalsePositiveAdjudicator::new());
    let containment = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());

    let config = OrchestratorConfig {
        mode: OrchestratorMode::Manual,
        db_dir: Some(temp_dir.path().to_path_buf()),
        consecutive_healthy_probes_required: 3,
        probe_interval_secs: 60,
        watchdog_max_secs: 1800,
    };

    let orch = KillSwitchOrchestrator::new(config, containment, adjudicator, lineage);

    orch.submit_threat(ThreatCandidate::new(
        Some(9999),
        "ransom.exe",
        "test",
        "Active encryption",
        0.95,
        killswitch_types::adjudication::EvidenceClass::Behavior,
    )).await.unwrap();

    let state = orch.get_state().await;
    assert_eq!(state.mode, OrchestratorMode::Manual);

    // Advance to Decide node
    for _ in 0..6 {

        let t = orch.step().await.unwrap();
        if t.from_stage == LifecycleStage::Decide {
            assert!(t.is_paused, "Manual mode without approval must be paused at Decide");
            break;
        }
    }

    // Now submit approval
    orch.submit_approval(OperatorApprovalState {
        decision: ApprovalDecision::Approved,
        operator_id: "secops_lead".to_string(),
        confirmation_token: "CONFIRM ISOLATE".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        comments: Some("Threat verified".to_string()),
    }).await.unwrap();

    let post_approval_state = orch.get_state().await;
    assert!(post_approval_state.operator_approval.is_some());
}

fn scan_dir_recursive(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_dir_recursive(&path, files);
            } else if path.extension().map_or(false, |ext| ext == "rs") {
                files.push(path);
            }
        }
    }
}

#[test]
fn test_zero_os_subprocess_spawning_in_orchestrator() {
    let orchestrator_src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    scan_dir_recursive(&orchestrator_src, &mut files);

    for path in &files {
        let content = std::fs::read_to_string(path).unwrap();
        assert!(!content.contains("Command::new(\"netsh"), "Forbidden netsh command in {:?}", path);
        assert!(!content.contains("Command::new(\"iptables"), "Forbidden iptables command in {:?}", path);
        assert!(!content.contains("Command::new(\"nft"), "Forbidden nft command in {:?}", path);
        assert!(!content.contains("Command::new(\"taskkill"), "Forbidden taskkill command in {:?}", path);
        assert!(!content.contains("Command::new(\"kill"), "Forbidden kill command in {:?}", path);
        assert!(!content.contains("Command::new(\"powershell"), "Forbidden powershell command in {:?}", path);
        assert!(!content.contains("Command::new(\"cmd"), "Forbidden cmd command in {:?}", path);
        assert!(!content.contains("Command::new(\"sc.exe"), "Forbidden sc.exe command in {:?}", path);
    }
    assert!(!files.is_empty(), "Must scan at least one .rs file in killswitch-orchestrator");
}

