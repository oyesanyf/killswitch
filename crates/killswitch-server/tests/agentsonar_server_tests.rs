//! Integration tests for `/api/agentsonar/*` HTTP endpoints, R4 loopback mutual
//! authentication (`401 Unauthorized` without valid token, `200 OK` with token),
//! AST-guarded `/api/agentsonar/classify`, and WebUI Card 11 zero-`innerHTML` invariant.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use killswitch_core::killchain::HostContainmentManager;
use killswitch_server::routes::build_router;
use killswitch_server::server::ServerState;

const TEST_MASTER_TOKEN: &str = "KS-TOKEN-AGENTSONAR-SERVER-TEST-2026-VERIFIED";

fn setup_server_state() -> Arc<ServerState> {
    let temp_dir = tempfile::tempdir().unwrap();
    let containment = Arc::new(
        HostContainmentManager::new_simulated_with_master_token(
            Some(temp_dir.path()),
            TEST_MASTER_TOKEN.to_string(),
        )
        .unwrap(),
    );
    let mut raw_state = ServerState::with_defaults(containment);
    raw_state.control_token = Arc::new(TEST_MASTER_TOKEN.to_string());
    raw_state
        .active_bound_port
        .store(0, std::sync::atomic::Ordering::SeqCst);
    Arc::new(raw_state)
}

async fn read_json(body: Body) -> serde_json::Value {
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

#[tokio::test]
async fn test_agentsonar_mutating_endpoints_enforce_r4_auth_and_crud() {
    let state = setup_server_state();

    // 1. Unauthenticated POST /api/agentsonar/agents -> 401 Unauthorized
    let unauth_req = Request::builder()
        .uri("/api/agentsonar/agents")
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "action": "add",
                "agent": "unauth-agent",
                "proc_pattern": "rogue*",
                "domain_pattern": "*.evil.example"
            }))
            .unwrap(),
        ))
        .unwrap();
    let unauth_resp = build_router(state.clone())
        .oneshot(unauth_req)
        .await
        .unwrap();
    assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Authenticated POST /api/agentsonar/agents -> 200 OK
    let auth_req = Request::builder()
        .uri("/api/agentsonar/agents")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-KillSwitch-Token", TEST_MASTER_TOKEN)
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "action": "add",
                "agent": "verified-api-agent",
                "proc_pattern": "verified_bin*",
                "domain_pattern": "*.perplexity.ai"
            }))
            .unwrap(),
        ))
        .unwrap();
    let auth_resp = build_router(state.clone()).oneshot(auth_req).await.unwrap();
    assert_eq!(auth_resp.status(), StatusCode::OK);
    let body = read_json(auth_resp.into_body()).await;
    assert_eq!(body["status"], "ok");

    // 3. GET /api/agentsonar/status & GET /api/agentsonar/osquery-schema
    let st_resp = build_router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/api/agentsonar/status")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(st_resp.status(), StatusCode::OK);
    let st_json = read_json(st_resp.into_body()).await;
    assert!(
        st_json["report"]["known_agents_count"]
            .as_u64()
            .unwrap_or(0)
            >= 6
    );

    let schema_resp = build_router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/api/agentsonar/osquery-schema")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(schema_resp.status(), StatusCode::OK);
    let schema_json = read_json(schema_resp.into_body()).await;
    assert!(schema_json["options"]["table_construction"]["agentsonar_events"].is_object());

    // 4. POST /api/agentsonar/classify scores flow and blocks privileged external_cmd
    let cls_req = Request::builder()
        .uri("/api/agentsonar/classify")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-KillSwitch-Token", TEST_MASTER_TOKEN)
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "event_jsonl": "{\"proc\":\"verified_bin\",\"domain\":\"api.perplexity.ai\",\"bytes_in\":50000,\"bytes_out\":2000,\"packets_in\":120,\"packets_out\":15,\"duration_ms\":9000}"
            }))
            .unwrap(),
        ))
        .unwrap();
    let cls_resp = build_router(state.clone()).oneshot(cls_req).await.unwrap();
    assert_eq!(cls_resp.status(), StatusCode::OK);
    let cls_json = read_json(cls_resp.into_body()).await;
    assert_eq!(cls_json["agent"], "verified-api-agent");
    assert_eq!(cls_json["scores"]["default"], 1.0);

    let bad_ext_req = Request::builder()
        .uri("/api/agentsonar/classify")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-KillSwitch-Token", TEST_MASTER_TOKEN)
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "event_jsonl": "{\"proc\":\"x\",\"domain\":\"example.com\"}",
                "external_cmd": "sudo -n evil_classifier"
            }))
            .unwrap(),
        ))
        .unwrap();
    let bad_ext_resp = build_router(state.clone())
        .oneshot(bad_ext_req)
        .await
        .unwrap();
    assert_eq!(bad_ext_resp.status(), StatusCode::BAD_REQUEST);

    // Cleanup test agent rule
    let cleanup_req = Request::builder()
        .uri("/api/agentsonar/agents")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-KillSwitch-Token", TEST_MASTER_TOKEN)
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "action": "remove",
                "agent": "verified-api-agent"
            }))
            .unwrap(),
        ))
        .unwrap();
    let _ = build_router(state.clone())
        .oneshot(cleanup_req)
        .await
        .unwrap();

    // 5. Verify WebUI includes Card 11 and strictly zero innerHTML assignments
    let ui_resp = build_router(state)
        .oneshot(
            Request::builder()
                .uri("/ui")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ui_resp.status(), StatusCode::OK);
    let ui_bytes = axum::body::to_bytes(ui_resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let ui_html = String::from_utf8_lossy(&ui_bytes);
    assert!(ui_html.contains("id=\"card-agentsonar\""));
    assert!(!ui_html.contains(".innerHTML"));
}
