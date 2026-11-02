//! In-memory and integration tests for `killswitch-server`.

use std::sync::Arc;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

async fn body_to_bytes(body: axum::body::Body) -> axum::body::Bytes {
    axum::body::to_bytes(body, usize::MAX).await.unwrap()
}

use killswitch_core::killchain::HostContainmentManager;
use killswitch_server::routes::build_router;
use killswitch_server::server::ServerState;
use killswitch_server::types::*;

fn setup_test_server_state() -> Arc<ServerState> {
    let temp_dir = tempfile::tempdir().unwrap();
    let containment = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());
    Arc::new(ServerState::with_defaults(containment))
}

#[tokio::test]
async fn test_server_status_and_history_endpoints() {
    let state = setup_test_server_state();
    let app = build_router(state);

    // 1. GET /status
    let req = Request::builder()
        .uri("/status")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = body_to_bytes(resp.into_body()).await;
    let status_res: StatusResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(!status_res.isolated);
    assert_eq!(status_res.active_mode, "autonomous");

    // 2. GET /history
    let req = Request::builder()
        .uri("/history")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = body_to_bytes(resp.into_body()).await;
    let hist_res: HistoryResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(hist_res.chain_valid);
}

#[tokio::test]
async fn test_server_engage_and_disarm_lifecycle() {
    let state = setup_test_server_state();
    let app = build_router(state);

    // 1. POST /engage
    let engage_body = serde_json::json!({
        "operator": "test_admin",
        "reason": "Test isolation verification",
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

    // Verify status is isolated
    let req = Request::builder()
        .uri("/status")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    let body_bytes = body_to_bytes(resp.into_body()).await;
    let status_res: StatusResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(status_res.isolated);

    // 2. POST /disarm
    let disarm_body = serde_json::json!({
        "operator": "test_admin",
        "reason": "Threat neutralized",
        "token": "CONFIRM RESTORE"
    });

    let req = Request::builder()
        .uri("/disarm")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&disarm_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify status is disarmed
    let req = Request::builder()
        .uri("/status")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    let body_bytes = body_to_bytes(resp.into_body()).await;
    let status_res: StatusResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(!status_res.isolated);
}

#[tokio::test]
async fn test_server_orchestrator_step_and_state() {
    let state = setup_test_server_state();
    let app = build_router(state);

    // 1. GET /graph/state
    let req = Request::builder()
        .uri("/graph/state")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = body_to_bytes(resp.into_body()).await;
    let state_res: GraphStateResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(state_res.trace_chain_valid);

    // 2. POST /graph/step
    let step_body = serde_json::json!({
        "step_input": {"test": "probe"},
        "force_node": null
    });

    let req = Request::builder()
        .uri("/graph/step")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&step_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = body_to_bytes(resp.into_body()).await;
    let step_res: GraphStepResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(step_res.executed_node, "IngestingSignals");

    // 3. POST /mode
    let mode_body = serde_json::json!({
        "mode": "manual",
        "operator": "test_lead"
    });

    let req = Request::builder()
        .uri("/mode")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&mode_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = body_to_bytes(resp.into_body()).await;
    let mode_res: ModeResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(mode_res.current_mode, "manual");
}

#[tokio::test]
async fn test_server_dlp_lineage_seed_and_evaluate() {
    let state = setup_test_server_state();
    let app = build_router(state.clone());

    // 1. POST /lineage/seed
    let seed_body = serde_json::json!({
        "path": "C:\\secrets\\intel.docx",
        "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "classification": "CrownJewel",
        "policy": "Quarantine",
        "inode_or_id": 999
    });

    let req = Request::builder()
        .uri("/lineage/seed")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&seed_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Manually register process reading file to taint it
    let file_key = killswitch_telemetry::otel_lineage::FileKey::from_path_or_synthetic("C:\\secrets\\intel.docx");
    let proc_key = killswitch_telemetry::otel_lineage::ProcessKey::new(8812, 1000, "curl.exe");
    state.lineage_engine.on_process_create(None, proc_key, "curl.exe");
    state.lineage_engine.on_file_read(proc_key, file_key);

    // 2. POST /lineage/evaluate
    let eval_body = serde_json::json!({
        "pid": 8812,
        "destination_url": "https://external-drop.example.com/exfil"
    });

    let req = Request::builder()
        .uri("/lineage/evaluate")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&eval_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = body_to_bytes(resp.into_body()).await;
    let eval_res: LineageEvaluateResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(eval_res.is_block);
    assert_eq!(eval_res.verdict, "Block");
    assert_eq!(eval_res.classification.unwrap(), "CrownJewel");
    assert_eq!(eval_res.policy.unwrap(), "Quarantine");

    // 3. GET /lineage/status
    let req = Request::builder()
        .uri("/lineage/status")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = body_to_bytes(resp.into_body()).await;
    let lin_res: LineageStatusResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(lin_res.tainted_processes_count >= 1);
}

fn scan_dir_recursive(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_dir_recursive(&path, files);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
}

#[test]
fn test_zero_os_subprocess_spawning_in_server() {
    let server_src = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    scan_dir_recursive(&server_src, &mut files);

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
    assert!(!files.is_empty(), "Must scan at least one .rs file in killswitch-server");
}

#[tokio::test]
async fn test_research_ingest_live_regression_probes() {
    let state = setup_test_server_state();
    let app = build_router(state);

    let ingest_body = serde_json::json!({
        "extractions": [
            {
                "arxiv_id": "2603.02277",
                "title": "Container Escape Probe",
                "attack_vector": "Docker daemon socket escape",
                "target_boundary": "container"
            },
            {
                "arxiv_id": "2610.09167",
                "title": "Conformal Jailbreak Defense",
                "attack_vector": "Multi-turn adversarial prompt inject",
                "target_boundary": "prompt"
            },
            {
                "arxiv_id": "2609.99999",
                "title": "Cloud IMDS SSRF Exploit",
                "attack_vector": "AWS metadata exfiltration",
                "target_boundary": "network_ssrf"
            }
        ]
    });

    let req = Request::builder()
        .uri("/api/research/ingest")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&ingest_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = body_to_bytes(resp.into_body()).await;
    let res: ResearchIngestResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(res.success);
    assert_eq!(res.ingested_count, 3);
    assert!(res.all_live_probes_executed);
    assert_eq!(res.coverage_percentage, 100.0);
    assert_eq!(res.containment_coverage.len(), 3);
    for report in &res.containment_coverage {
        assert!(report.live_probe_executed);
        assert!(report.live_probe_blocked);
        assert!(report.covered_by_killswitch);
        assert!(!report.target_crate_enhancement.is_empty());
    }
    assert!(!res.containment_coverage[1].is_novel_to_codebase);
    assert!(res.containment_coverage[0].is_novel_to_codebase);
    assert!(res.containment_coverage[2].is_novel_to_codebase);
    assert_eq!(res.novel_enhancement_count, 2);
    assert!(res.calibrated_sources_total >= 6);
}

#[tokio::test]
async fn test_research_menu_user_approval_gate_and_code_enforcement() {
    let state = setup_test_server_state();
    let app = build_router(state);

    // 1. Verify WebUI renders the Research Menu with User Approval controls
    let ui_req = Request::builder()
        .uri("/ui")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let ui_resp = app.clone().oneshot(ui_req).await.unwrap();
    assert_eq!(ui_resp.status(), StatusCode::OK);
    let ui_html = String::from_utf8(body_to_bytes(ui_resp.into_body()).await.to_vec()).unwrap();
    assert!(ui_html.contains("ArXiv &amp; LangExtract Security Research Menu (Mandatory User Approval Gate)"));
    assert!(ui_html.contains("approveSelectedResearch('approve', this)"));

    // 2. Discover/stage a new candidate in PendingApproval
    let discover_body = serde_json::json!({
        "arxiv_id": "2610.77777",
        "title": "Shadow Speculative Tool Execution Escape",
        "attack_vector": "Speculative tool pre-invocation sandbox bypass",
        "target_boundary": "mcp_tool_registry",
        "source_quote": "speculative pre-invocation shadow tool execution bypass",
        "target_crate_enhancement": "killswitch-telemetry"
    });
    let disc_req = Request::builder()
        .uri("/api/research/discover")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&discover_body).unwrap()))
        .unwrap();
    let disc_resp = app.clone().oneshot(disc_req).await.unwrap();
    assert_eq!(disc_resp.status(), StatusCode::OK);
    let menu: ResearchMenuResponse =
        serde_json::from_slice(&body_to_bytes(disc_resp.into_body()).await).unwrap();
    assert!(menu.user_approval_required);
    assert!(menu.candidates.iter().any(|c| c.arxiv_id == "2610.77777" && c.status == "PendingApproval"));

    // 3. Approve the staged candidate via POST /api/research/approve
    let approve_body = serde_json::json!({
        "candidate_id": "cand-2610-77777",
        "arxiv_id": "2610.77777",
        "decision": "approve",
        "operator": "secops_lead"
    });
    let app_req = Request::builder()
        .uri("/api/research/approve")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&approve_body).unwrap()))
        .unwrap();
    let app_resp = app.oneshot(app_req).await.unwrap();
    assert_eq!(app_resp.status(), StatusCode::OK);
    let app_res: ResearchApproveResponse =
        serde_json::from_slice(&body_to_bytes(app_resp.into_body()).await).unwrap();
    assert!(app_res.success);
    assert_eq!(app_res.candidate.status, "Approved");
    assert_eq!(app_res.candidate.approved_by.as_deref(), Some("secops_lead"));
    assert!(app_res.candidate.approval_seal_blake3.is_some());
    assert!(app_res.live_probe_verified);

    // 4. Verify the Rust ContinuousDefenseEngine actively blocks the newly approved research vector
    let verdict = killswitch_telemetry::global_continuous_defense().inspect_boundary(
        "mcp_invoke",
        "mcp_tool_registry",
        "attempting speculative pre-invocation shadow tool execution bypass on host",
        None,
        1,
    );
    assert!(!verdict.is_clean, "Approved research vector must be actively blocked by Rust code");
}


#[tokio::test]
async fn test_edr_behavioral_lineage_ioa_and_baseline_narrative_endpoints() {
    let state = setup_test_server_state();
    let app = build_router(state);

    // 1. Trigger LotL Word -> cmd -> encoded PowerShell -> external IP chain
    let req_lotl = Request::builder()
        .method("POST")
        .uri("/api/edr/behavioral/ingest")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "scenario": "lotl_word_powershell"
            })
            .to_string(),
        ))
        .unwrap();
    let resp_lotl = app.clone().oneshot(req_lotl).await.unwrap();
    assert_eq!(resp_lotl.status(), StatusCode::OK);
    let body_lotl = axum::body::to_bytes(resp_lotl.into_body(), usize::MAX)
        .await
        .unwrap();
    let json_lotl: serde_json::Value = serde_json::from_slice(&body_lotl).unwrap();
    assert_eq!(json_lotl["success"].as_bool(), Some(true));
    assert!(!json_lotl["narratives_emitted"].as_array().unwrap().is_empty());

    // 2. Trigger 3-anomaly statistical baseline correlation (service account recon + temp unsigned DLL + 3-sigma egress spike)
    let req_base = Request::builder()
        .method("POST")
        .uri("/api/edr/behavioral/ingest")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "scenario": "baseline_correlation"
            })
            .to_string(),
        ))
        .unwrap();
    let resp_base = app.clone().oneshot(req_base).await.unwrap();
    assert_eq!(resp_base.status(), StatusCode::OK);
    let body_base = axum::body::to_bytes(resp_base.into_body(), usize::MAX)
        .await
        .unwrap();
    let json_base: serde_json::Value = serde_json::from_slice(&body_base).unwrap();
    let narratives = json_base["narratives_emitted"].as_array().unwrap();
    let final_nar = narratives.last().unwrap();
    assert!(final_nar["composite_risk_score"].as_f64().unwrap() >= 0.85);
}


#[tokio::test]
async fn test_oshoosiclaw_research_accuracy_suite_and_4_gate_endpoints() {
    let state = setup_test_server_state();
    let app = build_router(state);

    // 1. POST /api/research/verify-accuracy
    let req_acc = Request::builder()
        .method("POST")
        .uri("/api/research/verify-accuracy")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp_acc = app.clone().oneshot(req_acc).await.unwrap();
    assert_eq!(resp_acc.status(), StatusCode::OK);
    let body_acc = axum::body::to_bytes(resp_acc.into_body(), usize::MAX).await.unwrap();
    let json_acc: serde_json::Value = serde_json::from_slice(&body_acc).unwrap();
    assert_eq!(json_acc["status"].as_str(), Some("verified"));
    assert_eq!(json_acc["true_positive_rate_pct"].as_f64(), Some(100.0));
    assert_eq!(json_acc["false_positive_rate_pct"].as_f64(), Some(0.0));
    assert_eq!(json_acc["byte_exact_parity"].as_bool(), Some(true));
    assert_eq!(json_acc["llm_fusion_consensus_passed"].as_bool(), Some(true));
    assert!(json_acc["total_rules_tested"].as_u64().unwrap_or(0) >= 4);

    // 2. POST /api/research/novelty-check
    let req_nov = Request::builder()
        .method("POST")
        .uri("/api/research/novelty-check")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "arxiv_ids": ["arXiv:2402.12345v1", "2610.09167", "2611.99999v1"]
            })
            .to_string(),
        ))
        .unwrap();
    let resp_nov = app.clone().oneshot(req_nov).await.unwrap();
    assert_eq!(resp_nov.status(), StatusCode::OK);
    let body_nov = axum::body::to_bytes(resp_nov.into_body(), usize::MAX).await.unwrap();
    let json_nov: serde_json::Value = serde_json::from_slice(&body_nov).unwrap();
    assert_eq!(json_nov["novel_count"].as_u64(), Some(1));
    assert_eq!(json_nov["already_implemented_count"].as_u64(), Some(2));

    // 3. POST /api/research/validate (rejects outdated 2024 paper)
    let req_val = Request::builder()
        .method("POST")
        .uri("/api/research/validate")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "rule": {
                    "rule_id": "ARXIV-DEF-2401.11111",
                    "arxiv_id": "2401.11111v1",
                    "title": "Outdated 2024 Preprint",
                    "attack_vector": "Container escape",
                    "target_boundary": "container_runtime_privilege",
                    "extraction_class": "breakout_vector",
                    "indicator_pattern": "/var/run/docker.sock | nsenter",
                    "cedar_forbid_policy": "",
                    "target_crate": "killswitch-telemetry",
                    "enrolled_at_utc": "2026-10-28T00:00:00Z"
                }
            })
            .to_string(),
        ))
        .unwrap();
    let resp_val = app.clone().oneshot(req_val).await.unwrap();
    assert_eq!(resp_val.status(), StatusCode::OK);
    let body_val = axum::body::to_bytes(resp_val.into_body(), usize::MAX).await.unwrap();
    let json_val: serde_json::Value = serde_json::from_slice(&body_val).unwrap();
    assert_eq!(json_val["accepted"].as_bool(), Some(false));
    assert_eq!(json_val["rejection_code"].as_str(), Some("RejectedOutdatedResearch"));
}


#[tokio::test]
async fn test_oshoosiclaw_oso_aws_apc_tamper_and_hitl_endpoints() {
    let state = setup_test_server_state();
    let app = build_router(state);

    // 1. GET /api/oso-aws-containment/status
    let req_oso = Request::builder()
        .method("GET")
        .uri("/api/oso-aws-containment/status")
        .body(Body::empty())
        .unwrap();
    let resp_oso = app.clone().oneshot(req_oso).await.unwrap();
    assert_eq!(resp_oso.status(), StatusCode::OK);

    // 2. POST /api/oso-aws-containment/watchdog-verify (simulate IAM policy swap -> triggers KillSwitch)
    let req_wd = Request::builder()
        .method("POST")
        .uri("/api/oso-aws-containment/watchdog-verify")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "simulate_policy_swap": true
            })
            .to_string(),
        ))
        .unwrap();
    let resp_wd = app.clone().oneshot(req_wd).await.unwrap();
    assert_eq!(resp_wd.status(), StatusCode::OK);
    let body_wd = axum::body::to_bytes(resp_wd.into_body(), usize::MAX).await.unwrap();
    let json_wd: serde_json::Value = serde_json::from_slice(&body_wd).unwrap();
    assert_eq!(json_wd["iam_policy_invariant_ok"].as_bool(), Some(false));
    assert_eq!(json_wd["kill_switch_engaged"].as_bool(), Some(true));

    // 3. POST /api/apc/evaluate (Bounded Agents APC arXiv:2608.15888)
    let req_apc = Request::builder()
        .method("POST")
        .uri("/api/apc/evaluate")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "principal_id": "principal-alice",
                "actor_id": "agent-worker-1",
                "action": "read_confidential",
                "resource": "docs/q3-financials",
                "data_classification": "CONFIDENTIAL",
                "task_session_id": "sess-apc-test-1"
            })
            .to_string(),
        ))
        .unwrap();
    let resp_apc = app.clone().oneshot(req_apc).await.unwrap();
    assert_eq!(resp_apc.status(), StatusCode::OK);
    let body_apc = axum::body::to_bytes(resp_apc.into_body(), usize::MAX).await.unwrap();
    let json_apc: serde_json::Value = serde_json::from_slice(&body_apc).unwrap();
    assert_eq!(json_apc["allowed"].as_bool(), Some(true));

    // Step 2 in same session: send_email -> blocked by C2_COMPOSITION
    let req_apc2 = Request::builder()
        .method("POST")
        .uri("/api/apc/evaluate")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "principal_id": "principal-alice",
                "actor_id": "agent-worker-1",
                "action": "send_email",
                "resource": "external/email",
                "data_classification": "PUBLIC",
                "task_session_id": "sess-apc-test-1"
            })
            .to_string(),
        ))
        .unwrap();
    let resp_apc2 = app.clone().oneshot(req_apc2).await.unwrap();
    assert_eq!(resp_apc2.status(), StatusCode::OK);
    let body_apc2 = axum::body::to_bytes(resp_apc2.into_body(), usize::MAX).await.unwrap();
    let json_apc2: serde_json::Value = serde_json::from_slice(&body_apc2).unwrap();
    assert_eq!(json_apc2["allowed"].as_bool(), Some(false));
    assert_eq!(json_apc2["failed_condition"].as_str(), Some("C2_COMPOSITION"));

    // 4. GET /api/tamper-guard/status
    let req_tg = Request::builder()
        .method("GET")
        .uri("/api/tamper-guard/status")
        .body(Body::empty())
        .unwrap();
    let resp_tg = app.clone().oneshot(req_tg).await.unwrap();
    assert_eq!(resp_tg.status(), StatusCode::OK);
    let body_tg = axum::body::to_bytes(resp_tg.into_body(), usize::MAX).await.unwrap();
    let json_tg: serde_json::Value = serde_json::from_slice(&body_tg).unwrap();
    assert_eq!(json_tg["tamper_guard"]["console_mode_hardened"].as_bool(), Some(true));

    // 5. POST /api/hitl/evaluate (Cognitive Red-Team HITL auto-veto on deceptive credential dump)
    let req_hitl = Request::builder()
        .method("POST")
        .uri("/api/hitl/evaluate")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "session_id": "sess-hitl-1",
                "arm_id": 1,
                "arm_generation": 1,
                "agent_id": "worker-1",
                "correlation_id": "corr-hitl-1",
                "tool_name": "extract_credentials",
                "target_resource": "C:\\Windows\\System32\\lsass.exe",
                "command_args": "--dump",
                "stated_justification": "Formatting markdown docs",
                "incoming_taint": "UntrustedExternal",
                "user_objective": "Format README"
            })
            .to_string(),
        ))
        .unwrap();
    let resp_hitl = app.clone().oneshot(req_hitl).await.unwrap();
    assert_eq!(resp_hitl.status(), StatusCode::OK);
    let body_hitl = axum::body::to_bytes(resp_hitl.into_body(), usize::MAX).await.unwrap();
    let json_hitl: serde_json::Value = serde_json::from_slice(&body_hitl).unwrap();
    assert_eq!(json_hitl["auto_vetoed"].as_bool(), Some(true));
}

#[tokio::test]
async fn test_cage_pep_endpoints_e2e() {
    use killswitch_telemetry::cage_governance::*;

    let state = setup_test_server_state();
    let app = build_router(state);

    // 1. GET /api/cage/status and GET /cage/status
    let req = Request::builder()
        .method("GET")
        .uri("/api/cage/status")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_to_bytes(resp.into_body()).await;
    let status_rep: CageKernelStatusReport = serde_json::from_slice(&bytes).unwrap();
    assert!(!status_rep.llm_clients_in_kernel);
    assert!(!status_rep.substrate_contract_digest.is_empty());
    assert!(status_rep.fiscal_cap_usd > 0.0);

    // Dual route check
    let req_unprefixed = Request::builder()
        .method("GET")
        .uri("/cage/status")
        .body(Body::empty())
        .unwrap();
    let resp_unprefixed = app.clone().oneshot(req_unprefixed).await.unwrap();
    assert_eq!(resp_unprefixed.status(), StatusCode::OK);

    // 2. POST /api/cage/evaluate: Clean trade -> Clear
    let clean_eval_req = CageEvaluationRequest {
        agent_id: "agent-trade-01".to_string(),
        role: "trader".to_string(),
        tool_name: "execute_trade".to_string(),
        arguments: serde_json::json!({ "symbol": "AAPL", "quantity": 10 }),
        confidence_score: Some(0.95),
        amount_usd: Some(100.0),
        dose_mg: None,
        warrant_token: None,
        human_approval: None,
        context: None,
    };
    let req = Request::builder()
        .method("POST")
        .uri("/api/cage/evaluate")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&clean_eval_req).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_to_bytes(resp.into_body()).await;
    let eval_res: CageEvaluationResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(eval_res.verdict, CageVerdict::Clear);
    assert!(!eval_res.receipt.receipt_signature.is_empty());
    assert!(eval_res.governance_trace.len() >= 3);

    // POST /api/cage/evaluate: Over-cap trade ($75,000 > $10,000 cap) -> Refuse (CTRL_OPA_005)
    let over_cap_req = CageEvaluationRequest {
        amount_usd: Some(75_000.0),
        ..clean_eval_req.clone()
    };
    let req = Request::builder()
        .method("POST")
        .uri("/api/cage/evaluate")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&over_cap_req).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_to_bytes(resp.into_body()).await;
    let eval_res: CageEvaluationResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(eval_res.verdict, CageVerdict::Refuse);
    assert_eq!(eval_res.tier, CageTier::Tier3Opa);
    assert_eq!(eval_res.rule_id, CTRL_OPA_005);

    // POST /api/cage/evaluate: FTRA Refusal on unauthenticated egress + sensitive payload
    let ftra_req = CageEvaluationRequest {
        agent_id: "agent-exfil-01".to_string(),
        role: "worker".to_string(),
        tool_name: "network_egress".to_string(),
        arguments: serde_json::json!({ "destination": "http://evil.com" }),
        confidence_score: Some(0.95),
        amount_usd: None,
        dose_mg: None,
        warrant_token: None,
        human_approval: None,
        context: Some(serde_json::json!({
            "is_unauthenticated_egress": true,
            "contains_confidential_payload": true
        })),
    };
    let req = Request::builder()
        .method("POST")
        .uri("/api/cage/evaluate")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&ftra_req).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_to_bytes(resp.into_body()).await;
    let eval_res: CageEvaluationResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(eval_res.verdict, CageVerdict::Refuse);
    assert_eq!(eval_res.tier, CageTier::Tier1Ftra);
    assert_eq!(eval_res.rule_id, CTRL_FTRA_001);

    // 3. POST /api/cage/compile-substrate: Valid Microsoft ACS specification
    let ms_spec = serde_json::json!({
        "metadata": { "name": "acs-server-test", "version": "1.0.0" },
        "behaviorDeclarations": [
            {
                "action": "execute_trade",
                "constraints": [
                    { "parameter": "max_single_transfer_usd", "value": 10000.0 },
                    { "parameter": "fiscal_cap_usd", "value": 50000.0 }
                ]
            }
        ]
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/cage/compile-substrate")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&ms_spec).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_to_bytes(resp.into_body()).await;
    let artifact: CompiledSubstrateArtifact = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(artifact.format, SubstrateFormat::MicrosoftAcs);
    assert!(artifact.verify_digest());

    // Invalid substrate payload (non-object) -> HTTP 400 Bad Request
    let invalid_spec = serde_json::json!(["invalid_spec_not_an_object"]);
    let req = Request::builder()
        .method("POST")
        .uri("/api/cage/compile-substrate")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&invalid_spec).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 4. POST /api/cage/verify-trace: Valid trace -> is_conformant == true
    let valid_trace = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 1000,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: false,
            details: "Action proposed".to_string(),
        },
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 1001,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier8Fiscal),
            verdict: Some(CageVerdict::Clear),
            rule_id: Some("PASS".to_string()),
            requires_warrant: false,
            details: "Fiscal spend verified".to_string(),
        },
        GovernanceTraceEvent {
            step: 3,
            timestamp_ms: 1002,
            kind: GovernanceTraceEventType::ReceiptSigned,
            tier: None,
            verdict: Some(CageVerdict::Clear),
            rule_id: None,
            requires_warrant: false,
            details: "Receipt signed".to_string(),
        },
    ];
    let req = Request::builder()
        .method("POST")
        .uri("/api/cage/verify-trace")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&valid_trace).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_to_bytes(resp.into_body()).await;
    let trace_rep: TraceConformanceReport = serde_json::from_slice(&bytes).unwrap();
    assert!(trace_rep.is_conformant);
    assert!(trace_rep.violations.is_empty());

    // POST /api/cage/verify-trace: Illegal trace (actuation after refusal) -> is_conformant == false
    let illegal_trace = vec![
        GovernanceTraceEvent {
            step: 1,
            timestamp_ms: 1000,
            kind: GovernanceTraceEventType::ActionProposed,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: false,
            details: "Action proposed".to_string(),
        },
        GovernanceTraceEvent {
            step: 2,
            timestamp_ms: 1001,
            kind: GovernanceTraceEventType::TierEvaluated,
            tier: Some(CageTier::Tier3Opa),
            verdict: Some(CageVerdict::Refuse),
            rule_id: Some(CTRL_OPA_005.to_string()),
            requires_warrant: false,
            details: "Over limit".to_string(),
        },
        GovernanceTraceEvent {
            step: 3,
            timestamp_ms: 1002,
            kind: GovernanceTraceEventType::ActuationCompleted,
            tier: None,
            verdict: None,
            rule_id: None,
            requires_warrant: false,
            details: "Actuated anyway!".to_string(),
        },
    ];
    let req = Request::builder()
        .method("POST")
        .uri("/api/cage/verify-trace")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&illegal_trace).unwrap()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_to_bytes(resp.into_body()).await;
    let trace_rep: TraceConformanceReport = serde_json::from_slice(&bytes).unwrap();
    assert!(!trace_rep.is_conformant);
    assert!(!trace_rep.violations.is_empty());
}

