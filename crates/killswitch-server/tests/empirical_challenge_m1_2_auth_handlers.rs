//! Empirical Challenge Test Suite: Server Auth, Handlers & Routing (Challenger 2)
//!
//! Objectives:
//! 1. POST /disarm authentication (Fail-Closed Phase 1):
//!    - Confirmation phrase "CONFIRM RESTORE" in body/Bearer/X-KillSwitch-Token -> 401 Unauthorized
//!    - Invalid token "WRONG_TOKEN" -> 401 Unauthorized
//!    - Missing/empty token -> 401 Unauthorized
//!    - Master token TEST_MASTER_TOKEN over real loopback TCP (kernel peer-PID verified) -> 200 OK
//! 2. EDR behavioral scenario ingestion:
//!    - Probe "reverse_shell", "lolbin_credential_dump", "ransomware_burst"
//!    - Verify both `/api/edr/behavioral/ingest` and `/api/edr-bench/ingest` routing
//! 3. SWE-bench evaluation:
//!    - Probe preset "broad_fail_pass_to_pass" -> 200 OK, vetoed (PASS_TO_PASS fails)
//!    - Probe preset "surgical_verified" -> 200 OK, promoted (PASS_TO_PASS passes)
//!    - Anti-blind-killswitch gate in POST /engage with broad rule -> vetoed
//! 4. Service lifecycle control endpoints:
//!    - GET /service/status & /api/service/status
//!    - POST /service/control with valid & invalid actions

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tower::ServiceExt;

use killswitch_core::killchain::HostContainmentManager;
use killswitch_server::routes::build_router;
use killswitch_server::server::ServerState;
use killswitch_types::status::KILLCHAIN_RESTORE_CONFIRMATION_PHRASE;

const TEST_MASTER_TOKEN: &str = "test_master_token_0123456789abcdef0123456789abcdef";

fn setup_test_server_state() -> (Arc<ServerState>, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().unwrap();
    let containment = Arc::new(
        HostContainmentManager::new_simulated_with_master_token(
            Some(temp_dir.path()),
            TEST_MASTER_TOKEN.to_string(),
        )
        .unwrap(),
    );
    let mut state = ServerState::with_defaults(containment);
    state.control_token = Arc::new(TEST_MASTER_TOKEN.to_string());
    state.active_bound_port.store(0, Ordering::SeqCst);
    (Arc::new(state), temp_dir)
}

async fn spawn_live_server(state: Arc<ServerState>) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    state.active_bound_port.store(port, Ordering::SeqCst);
    let app = build_router(state);
    let handle = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    (port, handle)
}

async fn body_to_json(body: axum::body::Body) -> serde_json::Value {
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ============================================================================
// 1. POST /disarm AUTHENTICATION EMPIRICAL CHALLENGES
// ============================================================================

#[tokio::test]
async fn test_disarm_with_confirm_restore_phrase_rejected_401() {
    let (state, _temp_dir) = setup_test_server_state();
    let (port, handle) = spawn_live_server(state).await;

    // Verify confirmation phrase matches constant
    assert_eq!(KILLCHAIN_RESTORE_CONFIRMATION_PHRASE, "CONFIRM RESTORE");

    let req_body = serde_json::json!({
        "operator": "secops_admin",
        "reason": "Threat neutralized and verified",
        "token": "CONFIRM RESTORE"
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/disarm", port))
        .json(&req_body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "POST /disarm with CONFIRM RESTORE must fail closed with 401 Unauthorized"
    );
    handle.abort();
}

#[tokio::test]
async fn test_disarm_with_confirm_restore_in_bearer_header_rejected_401() {
    let (state, _temp_dir) = setup_test_server_state();
    let (port, handle) = spawn_live_server(state).await;

    let req_body = serde_json::json!({
        "operator": "secops_admin",
        "reason": "Threat neutralized"
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/disarm", port))
        .header("Authorization", "Bearer CONFIRM RESTORE")
        .json(&req_body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "POST /disarm with Authorization: Bearer CONFIRM RESTORE must fail closed with 401"
    );
    handle.abort();
}

#[tokio::test]
async fn test_disarm_with_confirm_restore_in_x_killswitch_token_header_rejected_401() {
    let (state, _temp_dir) = setup_test_server_state();
    let (port, handle) = spawn_live_server(state).await;

    let req_body = serde_json::json!({
        "operator": "secops_admin",
        "reason": "Threat neutralized"
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/disarm", port))
        .header("X-KillSwitch-Token", "CONFIRM RESTORE")
        .json(&req_body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "POST /disarm with X-KillSwitch-Token: CONFIRM RESTORE must fail closed with 401"
    );
    handle.abort();
}

#[tokio::test]
async fn test_disarm_with_invalid_token_rejected_401() {
    let (state, _temp_dir) = setup_test_server_state();
    let app = build_router(state);

    let req_body = serde_json::json!({
        "operator": "attacker",
        "reason": "Unauthorized bypass attempt",
        "token": "WRONG_TOKEN"
    });

    let req = Request::builder()
        .uri("/disarm")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "POST /disarm with invalid token WRONG_TOKEN must be rejected with 401 Unauthorized"
    );
}

#[tokio::test]
async fn test_disarm_with_missing_or_empty_token_rejected_401() {
    let (state, _temp_dir) = setup_test_server_state();
    let app = build_router(state);

    // 1. Missing token field in body
    let req_body_empty = serde_json::json!({
        "operator": "unauth_caller",
        "reason": "No token provided"
    });

    let req = Request::builder()
        .uri("/disarm")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&req_body_empty).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "POST /disarm with missing token must return 401 Unauthorized"
    );

    // 2. Empty string token
    let req_body_empty_str = serde_json::json!({
        "operator": "unauth_caller",
        "reason": "Empty token string",
        "token": ""
    });

    let req = Request::builder()
        .uri("/disarm")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&req_body_empty_str).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "POST /disarm with empty token string must return 401 Unauthorized"
    );
}

#[tokio::test]
async fn test_disarm_with_master_token_succeeds_200() {
    let (state, _temp_dir) = setup_test_server_state();
    let (port, handle) = spawn_live_server(state).await;

    let req_body = serde_json::json!({
        "operator": "master_admin",
        "reason": "Authorized master disarm",
        "token": TEST_MASTER_TOKEN
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/disarm", port))
        .json(&req_body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "POST /disarm with valid master token over live loopback TCP must return 200 OK"
    );
    handle.abort();
}

// ============================================================================
// 2. EDR BEHAVIORAL SCENARIO INGESTION PROBES
// ============================================================================

#[tokio::test]
async fn test_edr_behavioral_ingest_reverse_shell() {
    let (state, _temp_dir) = setup_test_server_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/edr/behavioral/ingest")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-KillSwitch-Token", TEST_MASTER_TOKEN)
        .body(Body::from(
            serde_json::json!({
                "scenario": "reverse_shell"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_to_json(resp.into_body()).await;
    assert_eq!(json["success"].as_bool(), Some(true));
    assert!(
        json["events_processed"].as_u64().unwrap() >= 3,
        "reverse_shell scenario must generate and process >= 3 telemetry events"
    );
    assert!(
        !json["narratives_emitted"].as_array().unwrap().is_empty(),
        "reverse_shell scenario must emit attack chain narratives"
    );
}

#[tokio::test]
async fn test_edr_behavioral_ingest_lolbin_credential_dump() {
    let (state, _temp_dir) = setup_test_server_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/edr/behavioral/ingest")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-KillSwitch-Token", TEST_MASTER_TOKEN)
        .body(Body::from(
            serde_json::json!({
                "scenario": "lolbin_credential_dump"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_to_json(resp.into_body()).await;
    assert_eq!(json["success"].as_bool(), Some(true));
    assert!(
        json["events_processed"].as_u64().unwrap() >= 3,
        "lolbin_credential_dump scenario must process >= 3 events"
    );
    assert!(
        !json["narratives_emitted"].as_array().unwrap().is_empty(),
        "lolbin_credential_dump scenario must emit narratives"
    );
}

#[tokio::test]
async fn test_edr_behavioral_ingest_ransomware_burst() {
    let (state, _temp_dir) = setup_test_server_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/edr/behavioral/ingest")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-KillSwitch-Token", TEST_MASTER_TOKEN)
        .body(Body::from(
            serde_json::json!({
                "scenario": "ransomware_burst"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_to_json(resp.into_body()).await;
    assert_eq!(json["success"].as_bool(), Some(true));
    assert!(
        json["events_processed"].as_u64().unwrap() >= 2,
        "ransomware_burst scenario must generate file encrypt & vssadmin delete events"
    );
}

#[tokio::test]
async fn test_edr_behavioral_routing_empirical_check() {
    let (state, _temp_dir) = setup_test_server_state();
    let app = build_router(state);

    // Test canonical route: /api/edr/behavioral/ingest
    let req_canon = Request::builder()
        .uri("/api/edr/behavioral/ingest")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-KillSwitch-Token", TEST_MASTER_TOKEN)
        .body(Body::from(
            serde_json::json!({ "scenario": "reverse_shell" }).to_string(),
        ))
        .unwrap();
    let resp_canon = app.clone().oneshot(req_canon).await.unwrap();
    assert_eq!(resp_canon.status(), StatusCode::OK);

    // Test without /api prefix: /edr/behavioral/ingest
    let req_no_api = Request::builder()
        .uri("/edr/behavioral/ingest")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-KillSwitch-Token", TEST_MASTER_TOKEN)
        .body(Body::from(
            serde_json::json!({ "scenario": "reverse_shell" }).to_string(),
        ))
        .unwrap();
    let resp_no_api = app.clone().oneshot(req_no_api).await.unwrap();
    assert_eq!(resp_no_api.status(), StatusCode::OK);

    // Test alias route: /api/edr-bench/ingest
    let req_bench_ingest = Request::builder()
        .uri("/api/edr-bench/ingest")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-KillSwitch-Token", TEST_MASTER_TOKEN)
        .body(Body::from(
            serde_json::json!({ "scenario": "reverse_shell" }).to_string(),
        ))
        .unwrap();
    let resp_bench_ingest = app.oneshot(req_bench_ingest).await.unwrap();

    // Empirically verify whether /api/edr-bench/ingest is currently mapped or 404
    // We observe the actual status code to document in findings
    let status = resp_bench_ingest.status();
    println!("Empirical probe /api/edr-bench/ingest status: {}", status);
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_FOUND,
        "Expected either 200 OK (if aliased) or 404 NOT_FOUND (if only /api/edr/behavioral/ingest)"
    );
}

// ============================================================================
// 3. SWE-BENCH TWO-GATE EVALUATION PROBES
// ============================================================================

#[tokio::test]
async fn test_swe_bench_evaluate_broad_fail_pass_to_pass_preset() {
    let (state, _temp_dir) = setup_test_server_state();
    let app = build_router(state);

    // Request with preset "broad_fail_pass_to_pass"
    let req = Request::builder()
        .uri("/api/edr-bench/evaluate")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-KillSwitch-Token", TEST_MASTER_TOKEN)
        .body(Body::from(
            serde_json::json!({
                "preset": "broad_fail_pass_to_pass",
                "auto_refine": false,
                "engage_if_promoted": false
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_to_json(resp.into_body()).await;
    // Overbroad rule must catch threat (FAIL_TO_PASS = true) but have false positives (PASS_TO_PASS = false)
    assert_eq!(
        json["fail_to_pass_succeeded"].as_bool(),
        Some(true),
        "Broad rule must match target threat pattern"
    );
    assert_eq!(
        json["pass_to_pass_succeeded"].as_bool(),
        Some(false),
        "Broad rule must trigger false positives on benign baseline"
    );
    assert_eq!(
        json["promoted_to_production"].as_bool(),
        Some(false),
        "Broad rule must NOT be promoted to production"
    );
    assert!(
        json["false_positive_count"].as_u64().unwrap() > 0,
        "False positive count must be greater than 0"
    );
}

#[tokio::test]
async fn test_swe_bench_evaluate_surgical_verified_preset() {
    let (state, _temp_dir) = setup_test_server_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/edr-bench/evaluate")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-KillSwitch-Token", TEST_MASTER_TOKEN)
        .body(Body::from(
            serde_json::json!({
                "preset": "surgical_verified",
                "auto_refine": false,
                "engage_if_promoted": false
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let json = body_to_json(resp.into_body()).await;
    assert_eq!(json["fail_to_pass_succeeded"].as_bool(), Some(true));
    assert_eq!(json["pass_to_pass_succeeded"].as_bool(), Some(true));
    assert_eq!(json["promoted_to_production"].as_bool(), Some(true));
    assert_eq!(json["false_positive_count"].as_u64(), Some(0));
}

#[tokio::test]
async fn test_swe_bench_anti_blind_killswitch_vetoes_isolation_in_engage() {
    let (state, _temp_dir) = setup_test_server_state();
    let (port, handle) = spawn_live_server(state).await;

    // Overbroad candidate rule submitted to /engage
    let bad_rule =
        killswitch_adjudication::edr_bench::EdrBenchHarness::canonical_overbroad_blind_rule();

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/engage", port))
        .json(&serde_json::json!({
            "operator": "automated_candidate_detector",
            "reason": "Suspicious activity detected by untrusted rule",
            "token": TEST_MASTER_TOKEN,
            "candidate_rule": bad_rule
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let json: serde_json::Value = resp.json().await.unwrap();
    handle.abort();
    assert_eq!(
        json["success"].as_bool(),
        Some(false),
        "Engage with failing PASS_TO_PASS rule must NOT isolate"
    );
    assert_eq!(
        json["blind_killswitch_prevented"].as_bool(),
        Some(true),
        "blind_killswitch_prevented flag must be TRUE"
    );
    assert!(
        json["message"].as_str().unwrap().contains("VETOED"),
        "Veto message must explain SWE-Bench Anti-Blind-KillSwitch veto"
    );
}

// ============================================================================
// 4. SERVICE LIFECYCLE HANDLERS EMPIRICAL CHALLENGES
// ============================================================================

#[tokio::test]
async fn test_service_endpoints_status_and_control() {
    let (state, _temp_dir) = setup_test_server_state();
    let (port, handle) = spawn_live_server(state).await;

    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{}", port);

    // 1. GET /service/status
    let resp = client
        .get(format!("{}/service/status", base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // 2. GET /api/service/status alias
    let resp = client
        .get(format!("{}/api/service/status", base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // 3. POST /service/control status query (authenticated over live loopback TCP)
    let resp = client
        .post(format!("{}/service/control", base))
        .header("X-KillSwitch-Token", TEST_MASTER_TOKEN)
        .json(&serde_json::json!({
            "action": "status",
            "service_name": "killswitch"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // 4. POST /service/control invalid action must return 400 Validation Error
    let resp = client
        .post(format!("{}/service/control", base))
        .header("X-KillSwitch-Token", TEST_MASTER_TOKEN)
        .json(&serde_json::json!({
            "action": "bogus_unsupported_action",
            "service_name": "killswitch"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "Invalid service action must return 400 Bad Request"
    );
    handle.abort();
}
