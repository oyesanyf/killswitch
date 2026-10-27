//! # Empirical Adversarial Stress Test Suite — Milestone 5
//!
//! Rigorous empirical stress testing of `crates/killswitch-orchestrator` and `crates/killswitch-server`:
//! 1. Cyclic LangGraph transitions: rapid step iterations, recursion limits, rollback transitions.
//! 2. Tamper injection: corrupt checkpointer files and verify BLAKE3 trace chain detection immediately rejects tampered state.
//! 3. Ollama timeout stress: simulate offline and slow hanging Ollama server, verify 400ms timeout enforcement and fallback without crash.
//! 4. Axum server stress: concurrent requests, 3-strike 300s rate-limit lockout on bad credentials.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use killswitch_adjudication::ZeroFalsePositiveAdjudicator;
use killswitch_core::killchain::HostContainmentManager;
use killswitch_orchestrator::checkpointer::DurableFileCheckpointer;
use killswitch_orchestrator::engine::{KillSwitchOrchestrator, OrchestratorConfig};
use killswitch_orchestrator::graph::{LifecycleNode, StateGraphBuilder};
use killswitch_orchestrator::ollama::OllamaReasoningEngine;
use killswitch_orchestrator::state::LifecycleStage;
use killswitch_server::routes::build_router;
use killswitch_server::server::ServerState;
use killswitch_server::types::*;
use killswitch_telemetry::otel_lineage::EndpointLineageEngine;
use killswitch_types::errors::KillSwitchError;
use killswitch_types::graph::{
    GraphNodeId, GraphNodeOutput, KillSwitchGraphState, OrchestratorMode, StateCheckpointer,
};
use killswitch_types::status::{HealthProbeRunner, OperatorAuthenticator};

// =============================================================================
// Helper Fixtures
// =============================================================================

async fn body_to_bytes(body: axum::body::Body) -> axum::body::Bytes {
    axum::body::to_bytes(body, usize::MAX).await.unwrap()
}

fn setup_test_server_state() -> (Arc<ServerState>, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().unwrap();
    let containment =
        Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());
    (Arc::new(ServerState::with_defaults(containment)), temp_dir)
}

struct CyclicProbeNode {
    stage: LifecycleStage,
    containment: Arc<HostContainmentManager>,
    eligible_for_rollback: bool,
}

#[async_trait::async_trait]
impl LifecycleNode for CyclicProbeNode {
    fn stage(&self) -> LifecycleStage {
        self.stage
    }

    async fn execute(
        &self,
        state: &mut KillSwitchGraphState,
    ) -> killswitch_types::errors::Result<GraphNodeOutput> {
        let mut report = self.containment.run_probe()?;
        report.eligible_for_early_rollback = self.eligible_for_rollback;
        report.consecutive_healthy_probes = if self.eligible_for_rollback { 3 } else { 1 };
        state.probe_results.push(report);

        Ok(GraphNodeOutput {
            next_node: Some(self.stage.to_graph_node_id()),
            updated_threat_score: Some(state.aggregate_threat_score),
            candidate_updates: vec![],
            containment_action_taken: None,
            fraud_proofs_emitted: vec![],
            summary: format!("Executed {:?}", self.stage),
        })
    }
}

struct DummyStepNode(LifecycleStage);

#[async_trait::async_trait]
impl LifecycleNode for DummyStepNode {
    fn stage(&self) -> LifecycleStage {
        self.0
    }

    async fn execute(
        &self,
        _state: &mut KillSwitchGraphState,
    ) -> killswitch_types::errors::Result<GraphNodeOutput> {
        Ok(GraphNodeOutput {
            next_node: Some(self.0.to_graph_node_id()),
            updated_threat_score: None,
            candidate_updates: vec![],
            containment_action_taken: None,
            fraud_proofs_emitted: vec![],
            summary: format!("Step completed for {:?}", self.0),
        })
    }
}

// =============================================================================
// 1. Cyclic LangGraph Transitions & Bounds
// =============================================================================

#[tokio::test]
async fn test_challenge_cyclic_langgraph_rapid_step_iterations() {
    let temp_dir = tempfile::tempdir().unwrap();
    let lineage = Arc::new(EndpointLineageEngine::new_in_memory());
    let adjudicator = Arc::new(ZeroFalsePositiveAdjudicator::new());
    let containment =
        Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());

    let config = OrchestratorConfig {
        mode: OrchestratorMode::Autonomous,
        db_dir: Some(temp_dir.path().to_path_buf()),
        consecutive_healthy_probes_required: 3,
        probe_interval_secs: 60,
        watchdog_max_secs: 1800,
    };

    let orch = KillSwitchOrchestrator::new(config, containment, adjudicator, lineage);

    // Rapidly step through 60 iterations across the cyclic graph
    for step_num in 0..60 {
        let transition = orch.step().await.expect("Step transition must succeed");
        assert!(
            transition.duration_ms < 1000,
            "Step execution must complete in under 1 second"
        );

        let state = orch.get_state().await;
        // Verify BLAKE3 cryptographic chain integrity at EVERY iteration
        assert!(
            state.verify_trace_chain(),
            "BLAKE3 trace chain broken at step {}",
            step_num
        );
        assert_eq!(
            state.execution_trace.len(),
            step_num + 1,
            "Trace chain length must monotonically increase"
        );
    }
}

#[tokio::test]
async fn test_challenge_cyclic_langgraph_recursion_limit_enforcement() {
    // Construct an infinite loop: Ingest -> Correlate -> Ingest
    let builder = StateGraphBuilder::new()
        .add_node(LifecycleStage::Ingest, Arc::new(DummyStepNode(LifecycleStage::Ingest)))
        .add_node(LifecycleStage::Correlate, Arc::new(DummyStepNode(LifecycleStage::Correlate)))
        .add_edge(LifecycleStage::Ingest, LifecycleStage::Correlate)
        .add_edge(LifecycleStage::Correlate, LifecycleStage::Ingest)
        .set_entry_stage(LifecycleStage::Ingest)
        .set_max_cycle_depth(15);

    let graph = builder.compile();
    let mut state = KillSwitchGraphState::new("inc-cycle-limit-test", OrchestratorMode::Autonomous);

    // Run until terminal: must halt and fail with GraphHalted recursion limit
    let res = graph.run_until_pause_or_terminal(&mut state, LifecycleStage::Ingest).await;
    assert!(res.is_err(), "Must reject cyclic recursion beyond limit");

    match res.unwrap_err() {
        KillSwitchError::GraphHalted(msg) => {
            assert!(
                msg.contains("maximum cycle recursion limit of 15 steps"),
                "Expected recursion limit error message, got: {}",
                msg
            );
        }
        other => panic!("Expected GraphHalted error, got: {:?}", other),
    }

    // Verify exactly 15 steps were recorded and their BLAKE3 trace chain is intact
    assert_eq!(state.execution_trace.len(), 15);
    assert!(state.verify_trace_chain());
}

#[tokio::test]
async fn test_challenge_cyclic_langgraph_rollback_and_probe_lifecycle() {
    // Build a graph containing: Contain -> Monitor -> [Conditional: eligible -> Rollback, else -> Terminal] -> Terminal
    let temp_dir = tempfile::tempdir().unwrap();
    let containment =
        Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());

    // 1. Ineligible for rollback: should transition to Terminal without rolling back
    {
        let builder = StateGraphBuilder::new()
            .add_node(
                LifecycleStage::Monitor,
                Arc::new(CyclicProbeNode {
                    stage: LifecycleStage::Monitor,
                    containment: containment.clone(),
                    eligible_for_rollback: false,
                }),
            )
            .add_node(LifecycleStage::Terminal, Arc::new(DummyStepNode(LifecycleStage::Terminal)))
            .add_conditional_edge(
                LifecycleStage::Monitor,
                Arc::new(|state| {
                    if let Some(probe) = state.probe_results.last() {
                        if probe.eligible_for_early_rollback {
                            return LifecycleStage::Rollback;
                        }
                    }
                    LifecycleStage::Terminal
                }),
            );

        let graph = builder.compile();
        let mut state = KillSwitchGraphState::new("inc-probe-test-1", OrchestratorMode::Autonomous);
        let trans = graph.step(&mut state, LifecycleStage::Monitor).await.unwrap();

        assert_eq!(trans.to_stage, LifecycleStage::Terminal);
    }

    // 2. Eligible for rollback (3 clean probes): should transition to Rollback
    {
        let builder = StateGraphBuilder::new()
            .add_node(
                LifecycleStage::Monitor,
                Arc::new(CyclicProbeNode {
                    stage: LifecycleStage::Monitor,
                    containment: containment.clone(),
                    eligible_for_rollback: true,
                }),
            )
            .add_node(
                LifecycleStage::Rollback,
                Arc::new(killswitch_orchestrator::nodes::RollbackNode::new(containment.clone())),
            )
            .add_conditional_edge(
                LifecycleStage::Monitor,
                Arc::new(|state| {
                    if let Some(probe) = state.probe_results.last() {
                        if probe.eligible_for_early_rollback {
                            return LifecycleStage::Rollback;
                        }
                    }
                    LifecycleStage::Terminal
                }),
            );

        let graph = builder.compile();
        let mut state = KillSwitchGraphState::new("inc-probe-test-2", OrchestratorMode::Autonomous);
        state.containment_status.isolated = true;

        let trans1 = graph.step(&mut state, LifecycleStage::Monitor).await.unwrap();
        assert_eq!(trans1.to_stage, LifecycleStage::Rollback);

        let _trans2 = graph.step(&mut state, LifecycleStage::Rollback).await.unwrap();
        assert!(!state.containment_status.isolated, "Rollback must disarm isolation");
        assert!(state.verify_trace_chain());
    }
}

// =============================================================================
// 2. Tamper Injection into Checkpointer Files
// =============================================================================

#[tokio::test]
async fn test_challenge_checkpointer_tamper_injection_detection() {
    let temp_dir = tempfile::tempdir().unwrap();
    let checkpointer = DurableFileCheckpointer::new(temp_dir.path()).unwrap();
    let incident_id = "inc-tamper-challenge-001";

    let mut state = KillSwitchGraphState::new(incident_id, OrchestratorMode::Autonomous);
    state.record_execution_step(
        GraphNodeId::IngestingSignals,
        "input_digest_alpha",
        "output_digest_alpha",
        12,
        serde_json::json!({"action": "ingest", "signals": 5}),
    );
    state.record_execution_step(
        GraphNodeId::CorrelatingEdrAndOctopus,
        "input_digest_beta",
        "output_digest_beta",
        18,
        serde_json::json!({"action": "correlate", "score": 0.88}),
    );
    state.record_execution_step(
        GraphNodeId::AdjudicatingZeroFalsePositive,
        "input_digest_gamma",
        "output_digest_gamma",
        24,
        serde_json::json!({"action": "adjudicate", "verdict": "quarantine"}),
    );

    assert!(state.verify_trace_chain());
    checkpointer.save_checkpoint(&state).await.expect("Initial checkpoint save must succeed");

    // Verify clean load first
    let clean = checkpointer.load_checkpoint(incident_id).await.unwrap();
    assert!(clean.is_some());
    assert!(clean.unwrap().verify_trace_chain());

    let file_path = temp_dir.path().join(format!("checkpoint_{}.json", incident_id));
    assert!(file_path.exists());

    // Attack Scenario A: Tamper with step 1's output_digest on disk
    {
        let raw = std::fs::read_to_string(&file_path).unwrap();
        let tampered = raw.replace("output_digest_beta", "forged_adversarial_digest");
        std::fs::write(&file_path, tampered).unwrap();

        let load_res = checkpointer.load_checkpoint(incident_id).await;
        assert!(load_res.is_err(), "Must reject checkpoint with tampered output digest");
        match load_res.unwrap_err() {
            KillSwitchError::CryptoError(msg) => {
                assert!(msg.contains("BLAKE3 execution trace chain verification failed"));
            }
            other => panic!("Expected CryptoError, got: {:?}", other),
        }
    }

    // Attack Scenario B: Tamper with step 2's chain_hash directly
    {
        let raw = std::fs::read_to_string(&file_path).unwrap();
        // Replace a hex character in the chain hash
        let tampered = raw.replace("\"chain_hash\": \"", "\"chain_hash\": \"deadbeef");
        std::fs::write(&file_path, tampered).unwrap();

        let load_res = checkpointer.load_checkpoint(incident_id).await;
        assert!(load_res.is_err(), "Must reject checkpoint with tampered chain_hash");
    }

    // Attack Scenario C: Corrupt JSON structure / truncate
    {
        let raw = std::fs::read_to_string(&file_path).unwrap();
        let truncated = &raw[..raw.len() / 2];
        std::fs::write(&file_path, truncated).unwrap();

        let load_res = checkpointer.load_checkpoint(incident_id).await;
        assert!(load_res.is_err(), "Must fail safely on truncated/malformed checkpoint file");
    }
}

// =============================================================================
// 3. Ollama Timeout Stress & Dynamic Available Memory Law
// =============================================================================

#[test]
fn test_challenge_ollama_dynamic_memory_law_boundaries() {
    // Exact threshold boundary tests:
    // >= 48.0 GB -> qwen2.5:32b
    assert_eq!(OllamaReasoningEngine::select_model_from_free_ram_gb(64.0), "qwen2.5:32b");
    assert_eq!(OllamaReasoningEngine::select_model_from_free_ram_gb(48.0), "qwen2.5:32b");

    // 24.0 <= RAM < 48.0 -> qwen2.5:14b
    assert_eq!(OllamaReasoningEngine::select_model_from_free_ram_gb(47.99), "qwen2.5:14b");
    assert_eq!(OllamaReasoningEngine::select_model_from_free_ram_gb(24.0), "qwen2.5:14b");

    // 12.0 <= RAM < 24.0 -> qwen2.5:7b
    assert_eq!(OllamaReasoningEngine::select_model_from_free_ram_gb(23.99), "qwen2.5:7b");
    assert_eq!(OllamaReasoningEngine::select_model_from_free_ram_gb(12.0), "qwen2.5:7b");

    // 6.0 <= RAM < 12.0 -> qwen2.5:3b
    assert_eq!(OllamaReasoningEngine::select_model_from_free_ram_gb(11.99), "qwen2.5:3b");
    assert_eq!(OllamaReasoningEngine::select_model_from_free_ram_gb(6.0), "qwen2.5:3b");

    // RAM < 6.0 -> qwen2.5:1.5b
    assert_eq!(OllamaReasoningEngine::select_model_from_free_ram_gb(5.99), "qwen2.5:1.5b");
    assert_eq!(OllamaReasoningEngine::select_model_from_free_ram_gb(1.0), "qwen2.5:1.5b");
    assert_eq!(OllamaReasoningEngine::select_model_from_free_ram_gb(0.1), "qwen2.5:1.5b");

    // Invariant: Never append -coder
    for ram in [0.5, 3.0, 6.0, 9.0, 12.0, 18.0, 24.0, 36.0, 48.0, 96.0] {
        let model = OllamaReasoningEngine::select_model_from_free_ram_gb(ram);
        assert!(
            !model.contains("-coder"),
            "Model '{}' must not contain -coder suffix",
            model
        );
    }
}

#[tokio::test]
async fn test_challenge_ollama_offline_and_slow_hang_400ms_timeout() {
    // 1. Offline server: probe against a non-existent port
    {
        let engine = OllamaReasoningEngine::new("http://127.0.0.1:58291");
        let start = Instant::now();
        let res = engine.evaluate_forensics("Adversarial attack probe").await;
        let elapsed = start.elapsed();

        assert!(res.is_offline_fallback);
        assert_eq!(res.forensic_verdict, "CONFIRM_CONTAINMENT");
        assert!(res.confidence >= 0.90);
        assert!(res.model_used.contains("offline-rule-fallback"));
        assert!(
            elapsed < Duration::from_millis(800),
            "Offline check took {:?}, exceeding deadline threshold",
            elapsed
        );
    }

    // 2. Slow / Hanging server: simulate a server that accepts TCP connection but delays response for 1500ms
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let slow_server = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;
                // Intentionally delay 1500ms (exceeds 400ms timeout)
                tokio::time::sleep(Duration::from_millis(1500)).await;
                let body = "{\"response\": \"slow delayed answer\"}";
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = tokio::io::AsyncWriteExt::write_all(&mut socket, resp.as_bytes()).await;
            }
        });

        let engine = OllamaReasoningEngine::new(&format!("http://127.0.0.1:{}", port));
        let start = Instant::now();
        let res = engine.evaluate_forensics("Adversarial slow hang test").await;
        let elapsed = start.elapsed();

        slow_server.abort();

        // Must enforce 400ms timeout and fall back without hanging 1500ms
        assert!(
            res.is_offline_fallback,
            "Slow server must trigger offline fallback"
        );
        assert_eq!(res.forensic_verdict, "CONFIRM_CONTAINMENT");
        assert!(
            elapsed < Duration::from_millis(900),
            "Probe hung for {:?}; must be bounded by 400ms deadline",
            elapsed
        );
    }
}

// =============================================================================
// 4. Axum Server Stress & 3-Strike 300s Rate-Limit Lockout
// =============================================================================

#[tokio::test]
async fn test_challenge_axum_server_concurrent_request_stress() {
    let (state, _temp_dir) = setup_test_server_state();
    let app = build_router(state);

    // Launch 100 concurrent async requests across diverse API endpoints
    let mut handles = Vec::new();
    for i in 0..100 {
        let app_clone = app.clone();
        let endpoint = match i % 5 {
            0 => "/status",
            1 => "/history",
            2 => "/graph/state",
            3 => "/lineage/status",
            _ => "/octopus/arms",
        };

        handles.push(tokio::spawn(async move {
            let req = Request::builder()
                .uri(endpoint)
                .method("GET")
                .body(Body::empty())
                .unwrap();

            let resp = app_clone.oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "Concurrent request to {} must return 200 OK",
                endpoint
            );
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
}

#[tokio::test]
async fn test_challenge_axum_server_3_strike_rate_limit_lockout_and_bypass() {
    let (state, _temp_dir) = setup_test_server_state();
    let app = build_router(state.clone());

    // Isolate endpoint first
    let engage_body = serde_json::json!({
        "operator": "secops_admin",
        "reason": "Challenge test isolation",
        "token": "CONFIRM ISOLATE",
        "level": "network_quarantine"
    });
    let req = Request::builder()
        .uri("/engage")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&engage_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify initial lockout state is clean
    let mut init_lockout = state.containment_manager.check_lockout();
    assert!(!init_lockout.is_currently_locked());
    assert_eq!(init_lockout.failed_attempts, 0);

    let bad_disarm_body = serde_json::json!({
        "operator": "rogue_intruder",
        "reason": "Malicious attempt to disarm",
        "token": "invalid_forged_token_XYZ"
    });

    // Strikes 1, 2, and 3: each must fail authentication
    for strike in 1..=3 {
        let req = Request::builder()
            .uri("/disarm")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&bad_disarm_body).unwrap()))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "Strike {} must be rejected with 401 Unauthorized",
            strike
        );
    }

    // Verify that exactly after 3 strikes, the 300-second lockout is engaged!
    let mut locked_state = state.containment_manager.check_lockout();
    assert!(
        locked_state.is_currently_locked(),
        "Interface must be locked out after 3 failed strikes"
    );
    assert_eq!(locked_state.failed_attempts, 3);
    assert_eq!(locked_state.max_failed_attempts, 3);
    assert_eq!(locked_state.lockout_duration_secs, 300);
    assert!(
        locked_state.lockout_remaining_secs > 0 && locked_state.lockout_remaining_secs <= 300,
        "Remaining lockout duration must be between 1 and 300 seconds (got {})",
        locked_state.lockout_remaining_secs
    );

    // Strike 4: Attempting authentication during active lockout is rejected
    {
        let req = Request::builder()
            .uri("/disarm")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&bad_disarm_body).unwrap()))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        // Server rejects either 401 UNAUTHORIZED or 429 TOO_MANY_REQUESTS
        assert!(
            resp.status() == StatusCode::UNAUTHORIZED
                || resp.status() == StatusCode::TOO_MANY_REQUESTS,
            "Request during active lockout must be rejected"
        );
    }

    // Emergency Master Token Bypass: "CONFIRM RESTORE" must bypass the active 300s lockout
    {
        let master_body = serde_json::json!({
            "operator": "secops_admin",
            "reason": "Authorized emergency restore bypass",
            "token": "CONFIRM RESTORE"
        });

        let req = Request::builder()
            .uri("/disarm")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&master_body).unwrap()))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Master emergency restore token must bypass 300s lockout"
        );

        let body_bytes = body_to_bytes(resp.into_body()).await;
        let disarm_resp: DisarmResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert!(disarm_resp.success);
        assert!(!disarm_resp.status.isolated);

        // Lockout must be fully reset after master restore token
        let mut post_bypass_lockout = state.containment_manager.check_lockout();
        assert!(
            !post_bypass_lockout.is_currently_locked(),
            "Lockout must be cleared following master token bypass"
        );
        assert_eq!(post_bypass_lockout.failed_attempts, 0);
    }
}
