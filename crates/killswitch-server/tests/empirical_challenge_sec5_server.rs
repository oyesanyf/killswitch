//! Empirical Challenge Test Suite SEC-5-Server:
//! Siquery Relational SQL Discovery & Active EDR Control Plane Endpoints.
//!
//! Author: challenger_sec5_1 (teamwork_challenger)
//!
//! Stress-tests:
//! 1. POST /api/siquery/query authentication (missing headers, invalid tokens, 401 Unauthorized).
//! 2. Quarantined / frozen caller isolation checks (403 Forbidden).
//! 3. Mutating statement rejection (DROP, INSERT, UPDATE, etc. return 400 Bad Request).
//! 4. Valid queries across output formats (JSON, CSV, pretty table).
//! 5. Massive SQL payload stress (>1MB payload).
//! 6. 15-second execution timeout on indefinite recursive CTE queries.
//! 7. GET /api/siquery/tables, GET /api/siquery/edr-status, and POST /api/siquery/protect-sweep.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use killswitch_core::killchain::HostContainmentManager;
use killswitch_server::routes::build_router;
use killswitch_server::server::ServerState;

const CHALLENGE_MASTER_TOKEN: &str = "KS-TOKEN-SEC5-CHALLENGE-2026-CRYPTOGRAPHIC-SECRET";

fn setup_challenge_server_state() -> (Arc<ServerState>, Arc<HostContainmentManager>) {
    let temp_dir = tempfile::tempdir().unwrap();
    let containment = Arc::new(
        HostContainmentManager::new_simulated_with_master_token(
            Some(temp_dir.path()),
            CHALLENGE_MASTER_TOKEN.to_string(),
        )
        .unwrap(),
    );
    let mut raw_state = ServerState::with_defaults(containment.clone());
    raw_state.control_token = Arc::new(CHALLENGE_MASTER_TOKEN.to_string());
    raw_state
        .active_bound_port
        .store(0, std::sync::atomic::Ordering::SeqCst);
    (Arc::new(raw_state), containment)
}

async fn body_to_bytes(body: axum::body::Body) -> axum::body::Bytes {
    axum::body::to_bytes(body, usize::MAX).await.unwrap()
}

// ============================================================================
// 1. POST /api/siquery/query AUTHENTICATION & ACCESS CONTROL
// ============================================================================

#[tokio::test]
async fn test_siquery_query_auth_missing_token_401() {
    let (state, _) = setup_challenge_server_state();
    let app = build_router(state);

    let body = serde_json::json!({
        "query": "SELECT pid, name FROM processes LIMIT 5;"
    });

    let req = Request::builder()
        .uri("/api/siquery/query")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Request without authentication token MUST return 401"
    );

    let bytes = body_to_bytes(resp.into_body()).await;
    let err_str = String::from_utf8_lossy(&bytes);
    assert!(
        err_str.contains("Missing required authentication token")
            || err_str.contains("AuthenticationFailed"),
        "Error body must indicate missing token, got: {}",
        err_str
    );
}

#[tokio::test]
async fn test_siquery_query_auth_invalid_token_401() {
    let (state, _) = setup_challenge_server_state();
    let app = build_router(state);

    let body = serde_json::json!({
        "query": "SELECT pid, name FROM processes LIMIT 5;"
    });

    let req = Request::builder()
        .uri("/api/siquery/query")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-KillSwitch-Token", "FORGED-WRONG-TOKEN-99999")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "Request with invalid token MUST return 401"
    );
}

#[tokio::test]
async fn test_siquery_query_quarantined_caller_and_spoofing_verdicts() {
    let quarantined_peer_pid = 9988u32;
    let frozen_pids = vec![quarantined_peer_pid];

    // Case 1: Quarantined caller MUST be forbidden (403 Caller Quarantined)
    let auth_verdict = killswitch_server::auth::verify_control_plane_request_with_token(
        Some(CHALLENGE_MASTER_TOKEN),
        None,
        Some(quarantined_peer_pid),
        quarantined_peer_pid,
        &frozen_pids,
        CHALLENGE_MASTER_TOKEN,
    );
    assert_eq!(
        auth_verdict,
        killswitch_server::auth::AuthVerdict::Forbidden403CallerQuarantined,
        "Quarantined caller MUST be forbidden (403)"
    );

    // Case 2: PID spoofing (claimed 100 != actual 200) MUST be forbidden (403 PID Spoofing)
    let spoof_verdict = killswitch_server::auth::verify_control_plane_request_with_token(
        Some(CHALLENGE_MASTER_TOKEN),
        None,
        Some(100),
        200,
        &[],
        CHALLENGE_MASTER_TOKEN,
    );
    assert_eq!(
        spoof_verdict,
        killswitch_server::auth::AuthVerdict::Forbidden403PidSpoofing,
        "Spoofed caller PID MUST be rejected"
    );
}

// ============================================================================
// 2. VALID QUERIES & FORMATTERS (JSON, CSV, PRETTY)
// ============================================================================

#[tokio::test]
async fn test_siquery_query_valid_json_csv_pretty_formats() {
    let (state, _) = setup_challenge_server_state();
    let app = build_router(state);

    // 1. JSON (default)
    let body_json = serde_json::json!({
        "query": "SELECT 42 AS answer, 'killswitch' AS agent;"
    });
    let req = Request::builder()
        .uri("/api/siquery/query")
        .method("POST")
        .header("Content-Type", "application/json")
        .header(
            "Authorization",
            format!("Bearer {}", CHALLENGE_MASTER_TOKEN),
        )
        .body(Body::from(serde_json::to_vec(&body_json).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_to_bytes(resp.into_body()).await;
    let json_val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json_val["status"], "ok");
    assert_eq!(json_val["count"], 1);
    assert_eq!(json_val["rows"][0]["answer"], 42);

    // 2. CSV
    let body_csv = serde_json::json!({
        "query": "SELECT 42 AS answer, 'killswitch' AS agent;",
        "format": "csv"
    });
    let req = Request::builder()
        .uri("/api/siquery/query")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-KillSwitch-Token", CHALLENGE_MASTER_TOKEN)
        .body(Body::from(serde_json::to_vec(&body_csv).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_to_bytes(resp.into_body()).await;
    let json_val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json_val["status"], "ok");
    let csv_str = json_val["csv"].as_str().expect("CSV field");
    assert!(csv_str.contains("answer"));
    assert!(csv_str.contains("agent"));
    assert!(csv_str.contains("42|killswitch") || csv_str.contains("killswitch|42"));

    // 3. Pretty table
    let body_pretty = serde_json::json!({
        "query": "SELECT 42 AS answer, 'killswitch' AS agent;",
        "format": "pretty"
    });
    let req = Request::builder()
        .uri("/api/siquery/query")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-KillSwitch-Token", CHALLENGE_MASTER_TOKEN)
        .body(Body::from(serde_json::to_vec(&body_pretty).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body_to_bytes(resp.into_body()).await;
    let json_val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json_val["status"], "ok");
    let pretty_str = json_val["pretty"].as_str().expect("Pretty field");
    assert!(pretty_str.contains("+"));
    assert!(pretty_str.contains("answer"));
    assert!(pretty_str.contains("killswitch"));
}

// ============================================================================
// 3. MUTATING STATEMENT REJECTION VIA ENDPOINT
// ============================================================================

#[tokio::test]
async fn test_siquery_query_mutating_statement_rejection_400() {
    let (state, _) = setup_challenge_server_state();
    let app = build_router(state);

    let mutating_payloads = [
        "DROP TABLE processes;",
        "INSERT INTO processes (pid) VALUES (1);",
        "UPDATE processes SET pid = 1;",
        "DELETE FROM processes;",
        "CREATE TABLE evil (id INT);",
        "ATTACH DATABASE 'evil.db' AS evil;",
    ];

    for q in &mutating_payloads {
        let body = serde_json::json!({
            "query": q
        });

        let req = Request::builder()
            .uri("/api/siquery/query")
            .method("POST")
            .header("Content-Type", "application/json")
            .header("X-KillSwitch-Token", CHALLENGE_MASTER_TOKEN)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "Mutating query '{}' MUST return 400 Bad Request",
            q
        );
        let bytes = body_to_bytes(resp.into_body()).await;
        let err_msg = String::from_utf8_lossy(&bytes);
        assert!(
            err_msg.contains("Mutating SQL statements are forbidden")
                || err_msg.contains("Validation")
                || err_msg.contains("authorization denied"),
            "Error body must explain rejection: {}",
            err_msg
        );
    }
}

// ============================================================================
// 4. MASSIVE SQL PAYLOAD STRESS (>1MB)
// ============================================================================

#[tokio::test]
async fn test_siquery_query_massive_payload_stress() {
    let (state, _) = setup_challenge_server_state();
    let app = build_router(state);

    // Construct a massive 1.2 MB SQL query padded with benign comment
    let padding = "A".repeat(1_200_000);
    let massive_sql = format!("SELECT 1 AS probe /* {} */ ;", padding);
    assert!(massive_sql.len() > 1_200_000, "Payload must exceed 1MB");

    let body = serde_json::json!({
        "query": massive_sql
    });

    let req = Request::builder()
        .uri("/api/siquery/query")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-KillSwitch-Token", CHALLENGE_MASTER_TOKEN)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Massive >1MB query must be handled without crash or panic"
    );
    let bytes = body_to_bytes(resp.into_body()).await;
    let json_val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json_val["status"], "ok");
    assert_eq!(json_val["rows"][0]["probe"], 1);
}

// ============================================================================
// 5. 15-SECOND EXECUTION TIMEOUT MECHANISM
// ============================================================================

#[test]
fn test_siquery_query_15s_timeout_mechanism() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let (state, _) = setup_challenge_server_state();
        let app = build_router(state);

        // Deterministic infinite recursive counter guaranteed to exceed 15s across all runners
        let long_running_sql = "WITH RECURSIVE r(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM r WHERE x < 1000000000000) SELECT count(*) FROM r;";

        let body = serde_json::json!({
            "query": long_running_sql
        });

        let req = Request::builder()
            .uri("/api/siquery/query")
            .method("POST")
            .header("Content-Type", "application/json")
            .header("X-KillSwitch-Token", CHALLENGE_MASTER_TOKEN)
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();

        let start = Instant::now();
        let resp = app.oneshot(req).await.unwrap();
        let elapsed = start.elapsed();
        let status = resp.status();
        let bytes = body_to_bytes(resp.into_body()).await;
        let err_msg = String::from_utf8_lossy(&bytes);

        // Verify execution timed out after approximately 15 seconds
        assert!(
            elapsed.as_secs() >= 14,
            "Query must have run for at least 14-15 seconds before timing out, took: {:?}, status: {:?}, body: {}",
            elapsed,
            status,
            err_msg
        );
        assert!(
            elapsed.as_secs() <= 20,
            "Query timeout must trigger close to 15 seconds, took: {:?}",
            elapsed
        );

        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Timed out query must return 500 Internal Server Error"
        );

        assert!(
            err_msg.contains("timed out after 15 seconds"),
            "Error message must specify 15-second timeout, got: {}",
            err_msg
        );
    });

    rt.shutdown_background();
}

// ============================================================================
// 6. TABLES, EDR-STATUS, & PROTECT-SWEEP ENDPOINTS
// ============================================================================

#[tokio::test]
async fn test_siquery_tables_endpoint() {
    let (state, _) = setup_challenge_server_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/siquery/tables")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = body_to_bytes(resp.into_body()).await;
    let json_val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json_val["status"], "ok");

    let tables = json_val["tables"].as_array().expect("tables array");
    assert!(
        tables.len() >= 41,
        "Must expose >= 41 tables, got {}",
        tables.len()
    );
}

#[tokio::test]
async fn test_siquery_edr_status_endpoint() {
    let (state, _) = setup_challenge_server_state();
    let app = build_router(state);

    let req = Request::builder()
        .uri("/api/siquery/edr-status")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = body_to_bytes(resp.into_body()).await;
    let json_val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json_val["status"], "ok");
    assert_eq!(json_val["sweeps_executed"], 12);
    assert!(json_val["metrics"].is_object());
}

#[tokio::test]
async fn test_siquery_protect_sweep_endpoint_auth_and_execution() {
    let (state, _) = setup_challenge_server_state();
    let app = build_router(state);

    // Case 1: Missing auth header -> 401
    let req_no_auth = Request::builder()
        .uri("/api/siquery/protect-sweep")
        .method("POST")
        .body(Body::empty())
        .unwrap();

    let resp1 = app.clone().oneshot(req_no_auth).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::UNAUTHORIZED);

    // Case 2: Valid auth header -> 200 OK
    let req_auth = Request::builder()
        .uri("/api/siquery/protect-sweep")
        .method("POST")
        .header("X-KillSwitch-Token", CHALLENGE_MASTER_TOKEN)
        .body(Body::empty())
        .unwrap();

    let resp2 = app.oneshot(req_auth).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);

    let bytes = body_to_bytes(resp2.into_body()).await;
    let json_val: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json_val["status"], "ok");
    assert_eq!(json_val["sweeps_executed"], 12);
}
