//! Empirical Challenge Test Suite for Requirement R4:
//! Control Plane Mutual Authentication & Loopback Hardening in `crates/killswitch-server`.
//!
//! Author: challenger_sec4_1 (teamwork_challenger)

use std::net::SocketAddr;
use std::sync::Arc;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use subtle::ConstantTimeEq;
use tower::ServiceExt;

use killswitch_core::killchain::HostContainmentManager;
use killswitch_server::auth::{
    constant_time_token_match, extract_token_from_headers,
    verify_control_plane_request_with_token,
    AuthVerdict, DEFAULT_CONTROL_PLANE_HEADER,
};
use killswitch_server::routes::build_router;
use killswitch_server::server::ServerState;
use killswitch_types::status::KILLCHAIN_ISOLATE_CONFIRMATION_PHRASE;

const CHALLENGE_MASTER_TOKEN: &str = "KS-TOKEN-CHALLENGE-2026-CRYPTOGRAPHIC-SECRET-KEY";

fn setup_challenge_state() -> (Arc<ServerState>, Arc<HostContainmentManager>) {
    std::env::set_var("KILLSWITCH_MASTER_TOKEN", CHALLENGE_MASTER_TOKEN);
    std::env::set_var("KILLSWITCH_CONTROL_TOKEN", CHALLENGE_MASTER_TOKEN);
    let temp_dir = tempfile::tempdir().unwrap();
    let containment = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());
    let state = Arc::new(ServerState::with_defaults(containment.clone()));
    (state, containment)
}

async fn body_to_bytes(body: axum::body::Body) -> axum::body::Bytes {
    axum::body::to_bytes(body, usize::MAX).await.unwrap()
}

// ============================================================================
// 1. TIMING ATTACK RESISTANCE & CONSTANT-TIME MATCHING
// ============================================================================

#[test]
fn test_timing_resistance_subtle_ct_eq() {
    let expected = CHALLENGE_MASTER_TOKEN;
    assert!(constant_time_token_match(expected, expected));

    // Whitespace trimming behavior
    assert!(constant_time_token_match(&format!("  {}  ", expected), expected));
    assert!(constant_time_token_match(expected, &format!("  {}  \n", expected)));

    // Differing lengths must reject
    assert!(!constant_time_token_match("short", expected));
    assert!(!constant_time_token_match(expected, "short"));

    // Equal length but differing in the first character
    let mut bad_first = expected.to_string();
    bad_first.replace_range(0..1, if expected.starts_with('A') { "B" } else { "A" });
    assert_eq!(bad_first.len(), expected.len());
    assert!(!constant_time_token_match(&bad_first, expected));

    // Equal length but differing in the last character
    let mut bad_last = expected.to_string();
    let last_idx = bad_last.len() - 1;
    bad_last.replace_range(last_idx..last_idx + 1, "Z");
    assert_eq!(bad_last.len(), expected.len());
    assert!(!constant_time_token_match(&bad_last, expected));

    // Direct byte comparison using subtle::ConstantTimeEq
    let a = expected.as_bytes();
    let b = expected.as_bytes();
    let ct_res: bool = a.ct_eq(b).into();
    assert!(ct_res);
}

// ============================================================================
// 2. HEADER EXTRACTION BEHAVIOR & TOKEN SANITIZATION
// ============================================================================

#[test]
fn test_header_extraction_sanitization() {
    use axum::http::HeaderMap;

    // 1. Bearer standard
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer my_secret_token".parse().unwrap());
    assert_eq!(extract_token_from_headers(&headers), Some("my_secret_token".to_string()));

    // 2. Lowercase bearer
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "bearer my_secret_token".parse().unwrap());
    assert_eq!(extract_token_from_headers(&headers), Some("my_secret_token".to_string()));

    // 3. Malformed "Bearer " (empty)
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer ".parse().unwrap());
    assert_eq!(extract_token_from_headers(&headers), None);

    // 4. Malformed "Bearer    " (whitespace only)
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer    ".parse().unwrap());
    assert_eq!(extract_token_from_headers(&headers), None);

    // 5. X-KillSwitch-Token standard
    let mut headers = HeaderMap::new();
    headers.insert(DEFAULT_CONTROL_PLANE_HEADER, "custom_x_token".parse().unwrap());
    assert_eq!(extract_token_from_headers(&headers), Some("custom_x_token".to_string()));

    // 6. X-KillSwitch-Token empty
    let mut headers = HeaderMap::new();
    headers.insert(DEFAULT_CONTROL_PLANE_HEADER, "   ".parse().unwrap());
    assert_eq!(extract_token_from_headers(&headers), None);

    // 7. Missing headers
    let headers = HeaderMap::new();
    assert_eq!(extract_token_from_headers(&headers), None);
}

// ============================================================================
// 3. STANDALONE VERIFICATION ORACLE MATRIX (Module 6 Contract)
// ============================================================================

#[test]
fn test_verification_oracle_unauthenticated_and_malformed_tokens() {
    let frozen_pids = vec![400];
    let expected = CHALLENGE_MASTER_TOKEN;

    // Missing token (None, None)
    assert_eq!(
        verify_control_plane_request_with_token(None, None, Some(100), 100, &frozen_pids, expected),
        AuthVerdict::Unauthorized401
    );

    // Empty tokens
    assert_eq!(
        verify_control_plane_request_with_token(Some(""), None, Some(100), 100, &frozen_pids, expected),
        AuthVerdict::Unauthorized401
    );
    assert_eq!(
        verify_control_plane_request_with_token(None, Some("   "), Some(100), 100, &frozen_pids, expected),
        AuthVerdict::Unauthorized401
    );

    // Random fake token
    assert_eq!(
        verify_control_plane_request_with_token(Some("bad_token_123"), None, Some(100), 100, &frozen_pids, expected),
        AuthVerdict::Unauthorized401
    );

    // Confirmation phrase "CONFIRM ISOLATE" against expected master token must FAIL in standalone oracle
    assert_eq!(
        verify_control_plane_request_with_token(Some(KILLCHAIN_ISOLATE_CONFIRMATION_PHRASE), None, Some(100), 100, &frozen_pids, expected),
        AuthVerdict::Unauthorized401
    );

    // Valid master token -> Authorized
    assert_eq!(
        verify_control_plane_request_with_token(Some(expected), None, Some(100), 100, &frozen_pids, expected),
        AuthVerdict::Authorized
    );

    // Caller PID spoofing: claimed 100 != actual 200
    assert_eq!(
        verify_control_plane_request_with_token(Some(expected), None, Some(100), 200, &frozen_pids, expected),
        AuthVerdict::Forbidden403PidSpoofing
    );

    // Quarantined caller: actual 400 is in frozen_pids
    assert_eq!(
        verify_control_plane_request_with_token(Some(expected), None, Some(400), 400, &frozen_pids, expected),
        AuthVerdict::Forbidden403CallerQuarantined
    );
}

// ============================================================================
// 4. HTTP ENDPOINT VERIFICATION: POST /engage
// ============================================================================

#[tokio::test]
async fn test_http_engage_auth_boundaries() {
    let (state, _) = setup_challenge_state();
    let app = build_router(state);

    // Case 1: Unauthenticated request (no token in headers, no token in body) -> 401
    let body = serde_json::json!({
        "operator": "test_operator",
        "reason": "Containment test"
    });
    let req = Request::builder()
        .uri("/engage")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Unauthenticated /engage must return 401");

    // Case 2: Empty token in body ("") -> 401
    let body = serde_json::json!({
        "operator": "test_operator",
        "reason": "Containment test",
        "token": ""
    });
    let req = Request::builder()
        .uri("/engage")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Empty token /engage must return 401");

    // Case 3: Malformed Bearer header ("Bearer ") -> 401
    let body = serde_json::json!({
        "operator": "test_operator",
        "reason": "Containment test"
    });
    let req = Request::builder()
        .uri("/engage")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer ")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Malformed Bearer header /engage must return 401");

    // Case 4: Random fake token ("bad_token_123") -> 401
    let body = serde_json::json!({
        "operator": "test_operator",
        "reason": "Containment test",
        "token": "bad_token_123"
    });
    let req = Request::builder()
        .uri("/engage")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Fake token /engage must return 401");

    // Case 5: Confirmation phrase "CONFIRM ISOLATE" in body -> 200 OK
    let body = serde_json::json!({
        "operator": "test_operator",
        "reason": "Containment test",
        "token": "CONFIRM ISOLATE"
    });
    let req = Request::builder()
        .uri("/engage")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "'CONFIRM ISOLATE' on /engage must succeed with 200");

    // Case 6: Valid cryptographic control token in Authorization header -> 200 OK
    let body = serde_json::json!({
        "operator": "test_operator",
        "reason": "Containment test with token"
    });
    let req = Request::builder()
        .uri("/engage")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", CHALLENGE_MASTER_TOKEN))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "Valid cryptographic token on /engage must succeed with 200");
}

// ============================================================================
// 5. HTTP ENDPOINT VERIFICATION: POST /mode
// ============================================================================

#[tokio::test]
async fn test_http_mode_auth_boundaries() {
    let (state, _) = setup_challenge_state();
    let app = build_router(state);
    let loopback_addr = SocketAddr::from(([127, 0, 0, 1], 52123));

    // Case 1: Unauthenticated request over loopback (ConnectInfo present) -> 401
    let body = serde_json::json!({
        "mode": "manual",
        "operator": "test_operator"
    });
    let mut req = Request::builder()
        .uri("/mode")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(loopback_addr));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Unauthenticated loopback /mode must return 401");

    // Case 2: Confirmation phrase "CONFIRM ISOLATE" must FAIL with 401 on /mode
    let body = serde_json::json!({
        "mode": "manual",
        "operator": "test_operator",
        "token": "CONFIRM ISOLATE"
    });
    let mut req = Request::builder()
        .uri("/mode")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(loopback_addr));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "'CONFIRM ISOLATE' must FAIL on /mode with 401");

    // Case 3: Empty token ("") -> 401
    let body = serde_json::json!({
        "mode": "manual",
        "operator": "test_operator",
        "token": ""
    });
    let mut req = Request::builder()
        .uri("/mode")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(loopback_addr));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Empty token on /mode must return 401");

    // Case 4: Malformed Bearer header ("Bearer ") -> 401
    let body = serde_json::json!({
        "mode": "manual",
        "operator": "test_operator"
    });
    let mut req = Request::builder()
        .uri("/mode")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer ")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(loopback_addr));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Malformed Bearer on /mode must return 401");

    // Case 5: Fake token ("bad_token_123") -> 401
    let body = serde_json::json!({
        "mode": "manual",
        "operator": "test_operator",
        "token": "bad_token_123"
    });
    let mut req = Request::builder()
        .uri("/mode")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(loopback_addr));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Fake token on /mode must return 401");

    // Case 6: Valid cryptographic control token -> 200 OK
    let body = serde_json::json!({
        "mode": "manual",
        "operator": "test_operator"
    });
    let mut req = Request::builder()
        .uri("/mode")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", CHALLENGE_MASTER_TOKEN))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(loopback_addr));
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "Valid cryptographic token on /mode must succeed with 200");
}

// ============================================================================
// 6. HTTP ENDPOINT VERIFICATION: POST /rl/learn
// ============================================================================

#[tokio::test]
async fn test_http_rl_learn_auth_boundaries() {
    let (state, _) = setup_challenge_state();
    let app = build_router(state);

    let base_rl_body = serde_json::json!({
        "destination_url": "https://api.github.com/repos",
        "process_name": "git.exe",
        "payload_taint_level": 0.1,
        "ai_breakout_signal": 0.0,
        "is_legitimate_transaction": true
    });

    // Case 1: Unauthenticated request -> 401
    let req = Request::builder()
        .uri("/rl/learn")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&base_rl_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Unauthenticated /rl/learn must return 401");

    // Case 2: Confirmation phrase "CONFIRM ISOLATE" must FAIL with 401
    let mut body_confirm = base_rl_body.clone();
    body_confirm["token"] = serde_json::json!("CONFIRM ISOLATE");
    let req = Request::builder()
        .uri("/rl/learn")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body_confirm).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "'CONFIRM ISOLATE' on /rl/learn must return 401");

    // Case 3: Empty token ("") -> 401
    let mut body_empty = base_rl_body.clone();
    body_empty["token"] = serde_json::json!("");
    let req = Request::builder()
        .uri("/rl/learn")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body_empty).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Empty token on /rl/learn must return 401");

    // Case 4: Malformed Bearer ("Bearer ") -> 401
    let req = Request::builder()
        .uri("/rl/learn")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer ")
        .body(Body::from(serde_json::to_vec(&base_rl_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Malformed Bearer on /rl/learn must return 401");

    // Case 5: Fake token ("bad_token_123") -> 401
    let mut body_fake = base_rl_body.clone();
    body_fake["token"] = serde_json::json!("bad_token_123");
    let req = Request::builder()
        .uri("/rl/learn")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body_fake).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Fake token on /rl/learn must return 401");

    // Case 6: Valid cryptographic control token -> 200 OK
    let req = Request::builder()
        .uri("/rl/learn")
        .method("POST")
        .header("Content-Type", "application/json")
        .header(DEFAULT_CONTROL_PLANE_HEADER, CHALLENGE_MASTER_TOKEN)
        .body(Body::from(serde_json::to_vec(&base_rl_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "Valid cryptographic token on /rl/learn must succeed with 200");
}

// ============================================================================
// 7. HTTP ENDPOINT VERIFICATION: POST /rate-limit/allowlist
// ============================================================================

#[tokio::test]
async fn test_http_rate_limit_allowlist_auth_boundaries() {
    let (state, _) = setup_challenge_state();
    let app = build_router(state);

    let base_body = serde_json::json!({
        "destination_host": "api.anthropic.com",
        "protocol": "tcp",
        "pid": 9876,
        "reason": "Test allowlist entry"
    });

    // Case 1: Unauthenticated request -> 401
    let req = Request::builder()
        .uri("/rate-limit/allowlist")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&base_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Unauthenticated /rate-limit/allowlist must return 401");

    // Case 2: Confirmation phrase "CONFIRM ISOLATE" must FAIL with 401
    let mut body_confirm = base_body.clone();
    body_confirm["token"] = serde_json::json!("CONFIRM ISOLATE");
    let req = Request::builder()
        .uri("/rate-limit/allowlist")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body_confirm).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "'CONFIRM ISOLATE' on /rate-limit/allowlist must return 401");

    // Case 3: Empty token ("") -> 401
    let mut body_empty = base_body.clone();
    body_empty["token"] = serde_json::json!("");
    let req = Request::builder()
        .uri("/rate-limit/allowlist")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body_empty).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Empty token on /rate-limit/allowlist must return 401");

    // Case 4: Malformed Bearer ("Bearer ") -> 401
    let req = Request::builder()
        .uri("/rate-limit/allowlist")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer ")
        .body(Body::from(serde_json::to_vec(&base_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Malformed Bearer on /rate-limit/allowlist must return 401");

    // Case 5: Fake token ("bad_token_123") -> 401
    let mut body_fake = base_body.clone();
    body_fake["token"] = serde_json::json!("bad_token_123");
    let req = Request::builder()
        .uri("/rate-limit/allowlist")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body_fake).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "Fake token on /rate-limit/allowlist must return 401");

    // Case 6: Valid cryptographic control token -> 200 OK
    let req = Request::builder()
        .uri("/rate-limit/allowlist")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", CHALLENGE_MASTER_TOKEN))
        .body(Body::from(serde_json::to_vec(&base_body).unwrap()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "Valid cryptographic token on /rate-limit/allowlist must succeed with 200");
}

// ============================================================================
// 8. CALLER QUARANTINE & ANTI-SPOOFING VERIFICATION
// ============================================================================

fn setup_challenge_state_with_frozen_pid(frozen_pid: u32) -> Arc<ServerState> {
    std::env::set_var("KILLSWITCH_MASTER_TOKEN", CHALLENGE_MASTER_TOKEN);
    std::env::set_var("KILLSWITCH_CONTROL_TOKEN", CHALLENGE_MASTER_TOKEN);
    let temp_dir = tempfile::tempdir().unwrap();
    let isolator = killswitch_core::killchain::default_network_isolator();
    let freezer = Arc::new(killswitch_core::freeze::NativeProcessFreezer::new());
    let auth = Arc::new(killswitch_core::auth::OperatorAuthManager::new(
        None,
        Some(temp_dir.path().to_path_buf()),
    ));
    let ledger = Arc::new(parking_lot::RwLock::new(
        killswitch_core::state_ledger::StateLedger::open_or_init(Some(temp_dir.path())).unwrap(),
    ));

    {
        let mut l = ledger.write();
        let mut st = l.status().clone();
        st.frozen_pids = vec![frozen_pid];
        let _ = l.record_state_transition(st, None, None, "QUARANTINE", "secops", "quarantine pid");
    }

    let containment = Arc::new(killswitch_core::killchain::KillChainHostManager::new(
        isolator, freezer, auth, ledger,
    ));
    Arc::new(ServerState::with_defaults(containment))
}

#[tokio::test]
async fn test_http_quarantined_caller_pid_rejection() {
    let state = setup_challenge_state_with_frozen_pid(7777);
    assert!(state.containment_manager.get_status().frozen_pids.contains(&7777));

    let app = build_router(state);

    // Call /engage presenting valid master token, but claiming caller_pid 7777 (which is quarantined)
    let body = serde_json::json!({
        "operator": "test_operator",
        "reason": "Containment engage from frozen process",
        "token": CHALLENGE_MASTER_TOKEN,
        "caller_pid": 7777
    });

    let req = Request::builder()
        .uri("/engage")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "Quarantined caller PID 7777 must return 403 Forbidden on /engage"
    );

    let body_bytes = body_to_bytes(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(json["error"]["code"], "CALLER_QUARANTINED");

    // Also verify /rate-limit/allowlist rejects quarantined caller PID
    let rl_body = serde_json::json!({
        "destination_host": "evil-exfil.com",
        "caller_pid": 7777,
        "token": CHALLENGE_MASTER_TOKEN
    });
    let req = Request::builder()
        .uri("/rate-limit/allowlist")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&rl_body).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "Quarantined caller PID 7777 must return 403 Forbidden on /rate-limit/allowlist"
    );
}

#[tokio::test]
async fn test_adversarial_in_memory_mode_unauthenticated_bypass_finding() {
    let (state, _) = setup_challenge_state();
    let app = build_router(state);

    // ADVERSARIAL CHALLENGE VERIFICATION:
    // When ConnectInfo is absent (e.g. in-memory test, IPC bridge, or reverse proxy not forwarding ConnectInfo),
    // /mode MUST fail closed with 401 Unauthorized across all unauthenticated requests.
    let mode_body = serde_json::json!({
        "mode": "manual",
        "operator": "adversary_without_token"
    });

    let req = Request::builder()
        .uri("/mode")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&mode_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "In-memory /mode request without token (ConnectInfo absent) must fail closed with 401 Unauthorized"
    );

    // Case 2: In-memory /mode with empty token in body must also fail closed with 401
    let empty_token_body = serde_json::json!({
        "mode": "manual",
        "operator": "adversary_empty_token",
        "token": ""
    });
    let req_empty = Request::builder()
        .uri("/mode")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&empty_token_body).unwrap()))
        .unwrap();
    let resp_empty = app.clone().oneshot(req_empty).await.unwrap();
    assert_eq!(resp_empty.status(), StatusCode::UNAUTHORIZED);

    // Case 3: In-memory /mode with valid cryptographic control token must succeed with 200 OK
    let auth_mode_body = serde_json::json!({
        "mode": "manual",
        "operator": "authorized_operator",
        "token": CHALLENGE_MASTER_TOKEN
    });
    let req_auth = Request::builder()
        .uri("/mode")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&auth_mode_body).unwrap()))
        .unwrap();
    let resp_auth = app.oneshot(req_auth).await.unwrap();
    assert_eq!(resp_auth.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_live_tcp_loopback_caller_pid_spoofing_detection() {
    let (state, _) = setup_challenge_state();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();
    let port = local_addr.port();
    state.active_bound_port.store(port, std::sync::atomic::Ordering::SeqCst);

    let app = build_router(state);
    let server_handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await;
    });

    // Give server a moment to spin up
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/engage", port);

    // 1. Spoofed PID: Our actual PID is std::process::id(). We claim std::process::id() + 99999.
    let my_pid = std::process::id();
    let spoof_body = serde_json::json!({
        "operator": "spoofed_agent",
        "reason": "Spoofed PID test",
        "token": CHALLENGE_MASTER_TOKEN,
        "caller_pid": my_pid + 99999
    });

    let resp = client.post(&url)
        .json(&spoof_body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "Spoofed caller PID over real loopback TCP socket MUST return 403 Forbidden"
    );

    let err_json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        err_json["error"]["code"],
        "CALLER_PID_SPOOFED",
        "Error code must be CALLER_PID_SPOOFED"
    );

    // 2. Legitimate PID: Claim actual PID std::process::id() over real TCP socket
    let legit_body = serde_json::json!({
        "operator": "legit_agent",
        "reason": "Legit PID test",
        "token": CHALLENGE_MASTER_TOKEN,
        "caller_pid": my_pid
    });

    let resp_legit = client.post(&url)
        .json(&legit_body)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp_legit.status(),
        reqwest::StatusCode::OK,
        "Matching caller PID over real loopback TCP socket MUST succeed with 200 OK"
    );

    server_handle.abort();
}

