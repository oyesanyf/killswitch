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
