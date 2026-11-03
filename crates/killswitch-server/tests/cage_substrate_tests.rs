//! Integration tests covering all 6 CAGE Substrate Endpoints:
//! 1. GET /.well-known/jwks.json
//! 2. GET /v1/cage/normative-baseline/{region}
//! 3. GET /v1/cage/attest
//! 4. POST /v1/cage/conformal/validate
//! 5. POST /v1/cage/quarantine
//! 6. POST /v1/cage/release

use std::sync::Arc;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde_json::json;
use tower::ServiceExt;

use killswitch_core::killchain::HostContainmentManager;
use killswitch_server::journal::QuarantineLease;
use killswitch_server::routes::build_router;
use killswitch_server::server::ServerState;
use killswitch_server::types::*;

async fn body_to_bytes(body: axum::body::Body) -> axum::body::Bytes {
    axum::body::to_bytes(body, usize::MAX).await.unwrap()
}

fn setup_test_server_state() -> Arc<ServerState> {
    std::env::set_var(
        "KILLSWITCH_MASTER_TOKEN",
        "test_master_token_0123456789abcdef0123456789abcdef",
    );
    let temp_dir = tempfile::tempdir().unwrap();
    let containment =
        Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());
    Arc::new(ServerState::with_defaults(containment))
}

#[tokio::test]
async fn test_substrate_endpoint_1_jwks() {
    let state = setup_test_server_state();
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri("/.well-known/jwks.json")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );

    let body_bytes = body_to_bytes(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    let keys = json.get("keys").and_then(|k| k.as_array()).expect("keys array");
    assert!(!keys.is_empty(), "JWKS must contain at least one key");

    let key = &keys[0];
    assert_eq!(key.get("kty").unwrap(), "OKP");
    assert_eq!(key.get("crv").unwrap(), "Ed25519");
    assert_eq!(key.get("use").unwrap(), "sig");
    assert_eq!(key.get("kid").unwrap(), state.ed25519_kid.as_str());

    let x_b64 = key.get("x").unwrap().as_str().unwrap();
    let x_bytes = URL_SAFE_NO_PAD.decode(x_b64).expect("valid base64url x");
    assert_eq!(x_bytes.len(), 32);

    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&x_bytes);
    let pub_key = VerifyingKey::from_bytes(&key_arr).expect("valid public key");
    assert_eq!(pub_key, state.signing_key.verifying_key());
}

#[tokio::test]
async fn test_substrate_endpoint_2_normative_baseline() {
    let state = setup_test_server_state();
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri("/v1/cage/normative-baseline/europe-west1")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = body_to_bytes(resp.into_body()).await;
    let baseline: CageConformalBaselineResponse = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(baseline.region, "europe-west1");
    assert_eq!(baseline.alpha, 0.05);
    assert_eq!(baseline.calibration_size, 500);
    assert_eq!(baseline.nonconformity_threshold, 4.25);
    assert_eq!(baseline.kid, state.ed25519_kid);

    // Verify Ed25519 signature
    let unsigned_val = json!({
        "region": baseline.region,
        "alpha": baseline.alpha,
        "calibration_size": baseline.calibration_size,
        "nonconformity_threshold": baseline.nonconformity_threshold,
        "timestamp_utc": baseline.timestamp_utc,
        "kid": baseline.kid
    });
    let canonical = killswitch_telemetry::canonicalize_jcs(&unsigned_val).unwrap();
    let mut preimage = b"CAGE_CONFORMAL_BASELINE_V1:".to_vec();
    preimage.extend_from_slice(&canonical);

    let sig_bytes = URL_SAFE_NO_PAD.decode(&baseline.signature).unwrap();
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    assert!(state.signing_key.verifying_key().verify(&preimage, &sig).is_ok());
}

#[tokio::test]
async fn test_substrate_endpoint_3_attest() {
    let state = setup_test_server_state();
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .uri("/v1/cage/attest")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = body_to_bytes(resp.into_body()).await;
    let attestation: CageAttestationResponse = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(attestation.attestation_type, "HOST_TPM_PCR");
    assert!(!attestation.ring0_posture.is_empty());
    assert!(!attestation.pcr_values.is_empty());
    assert_eq!(attestation.kid, state.ed25519_kid);

    // Verify signature
    let unsigned_val = json!({
        "attestation_type": attestation.attestation_type,
        "ring0_posture": attestation.ring0_posture,
        "tpm_pcr_quote": attestation.tpm_pcr_quote,
        "pcr_values": attestation.pcr_values,
        "timestamp_utc": attestation.timestamp_utc,
        "kid": attestation.kid
    });
    let canonical = killswitch_telemetry::canonicalize_jcs(&unsigned_val).unwrap();
    let mut preimage = b"CAGE_ATTESTATION_RECEIPT_V1:".to_vec();
    preimage.extend_from_slice(&canonical);

    let sig_bytes = URL_SAFE_NO_PAD.decode(&attestation.signature).unwrap();
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    assert!(state.signing_key.verifying_key().verify(&preimage, &sig).is_ok());
}

#[tokio::test]
async fn test_substrate_endpoint_4_conformal_validate() {
    let state = setup_test_server_state();
    let app = build_router(Arc::clone(&state));

    // 4a. Conforming score (0.5) -> Admitted = true, CONSENSUS_ALLOW
    let req_body_allow = json!({
        "scores": [0.5],
        "alpha": 0.05,
        "action": "execute_read_query",
        "nonce": "nonce_conformal_test_001"
    });

    let req = Request::builder()
        .uri("/v1/cage/conformal/validate")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body_allow).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = body_to_bytes(resp.into_body()).await;
    let val_resp: CageConformalValidateResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(val_resp.admitted, "Score 0.5 must be admitted");
    assert!(val_resp.p_value > 0.05, "P-value must exceed alpha");
    assert_eq!(val_resp.voter_consensus, "CONSENSUS_ALLOW");

    // 4b. Anti-replay protection on duplicate nonce
    let req_replay = Request::builder()
        .uri("/v1/cage/conformal/validate")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body_allow).unwrap()))
        .unwrap();

    let resp_replay = app.clone().oneshot(req_replay).await.unwrap();
    assert_eq!(resp_replay.status(), StatusCode::CONFLICT);

    // 4c. Non-conforming score (20.0) -> Admitted = false, CONSENSUS_DENY
    let req_body_deny = json!({
        "scores": [20.0],
        "alpha": 0.05,
        "action": "privilege_escalation_bypass",
        "nonce": "nonce_conformal_test_002"
    });

    let req = Request::builder()
        .uri("/v1/cage/conformal/validate")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body_deny).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = body_to_bytes(resp.into_body()).await;
    let val_resp: CageConformalValidateResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(!val_resp.admitted, "Score 20.0 must be rejected as non-conforming");
    assert!(val_resp.p_value <= 0.05, "P-value must not exceed alpha");
    assert_eq!(val_resp.voter_consensus, "CONSENSUS_DENY");
}

#[tokio::test]
async fn test_substrate_endpoint_5_quarantine() {
    let state = setup_test_server_state();
    let app = build_router(Arc::clone(&state));

    // Generate CAGE signer keypair and register in state
    let signer_key = SigningKey::generate(&mut OsRng);
    let signer_kid = "cage-signer-kid-test-0000000001".to_string();
    state
        .cage_key_manifest
        .register_key(&signer_kid, signer_key.verifying_key());

    let directive = json!({
        "workload_id": "test-workload-quarantine-01",
        "target_pid": 12345,
        "trigger_reason": "CBF lethal barrier violation detected by CAGE kernel",
        "rule_id": "RULE-SC-7-CBF-LETHAL",
        "nonce": "nonce_quarantine_test_001"
    });

    let canonical_body = killswitch_telemetry::canonicalize_jcs(&directive).unwrap();
    let mut preimage = b"CAGE_QUARANTINE_ASSERTION_V1:".to_vec();
    preimage.extend_from_slice(&canonical_body);

    let sig = signer_key.sign(&preimage);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    let req = Request::builder()
        .uri("/v1/cage/quarantine")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-CAGE-Quarantine-Assertion", sig_b64)
        .header("X-CAGE-Signer-Kid", &signer_kid)
        .body(Body::from(canonical_body.clone()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = body_to_bytes(resp.into_body()).await;
    let receipt: CageQuarantineReceiptResponse = serde_json::from_slice(&body_bytes).unwrap();

    assert_eq!(receipt.status, "QUARANTINED");
    assert!(receipt.quarantined);
    assert_eq!(receipt.enforcement_plane, "HOST_OS_KERNEL");
    assert_eq!(receipt.kid, state.ed25519_kid);
    assert_eq!(receipt.target_pid, Some(12345));
    assert!(!receipt.signature.is_empty());

    // Verify lease is active in journal
    let active_leases = state.journal.unexpired_leases();
    assert_eq!(active_leases.len(), 1);
    assert_eq!(active_leases[0].workload_id, "test-workload-quarantine-01");

    // Anti-replay: identical nonce rejected
    let req_replay = Request::builder()
        .uri("/v1/cage/quarantine")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-CAGE-Quarantine-Assertion", receipt.signature)
        .header("X-CAGE-Signer-Kid", &signer_kid)
        .body(Body::from(canonical_body))
        .unwrap();

    let resp_replay = app.oneshot(req_replay).await.unwrap();
    assert_ne!(resp_replay.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_substrate_endpoint_6_release() {
    let state = setup_test_server_state();
    let app = build_router(Arc::clone(&state));

    // Register active quarantine lease first
    let lease = QuarantineLease {
        workload_id: "test-workload-release-01".to_string(),
        target_pid: Some(54321),
        trigger_reason: "Initial quarantine".to_string(),
        rule_id: "RULE_TEST".to_string(),
        quarantined_at: chrono::Utc::now(),
        expires_at: None,
        nonce: "init_nonce_001".to_string(),
    };
    state.journal.record_quarantine(lease).unwrap();
    assert_eq!(state.journal.unexpired_leases().len(), 1);
    assert_eq!(state.journal.get_generation_epoch("test-workload-release-01"), 1);

    // Generate CAGE signer keypair and register in state
    let signer_key = SigningKey::generate(&mut OsRng);
    let signer_kid = "cage-signer-kid-test-0000000002".to_string();
    state
        .cage_key_manifest
        .register_key(&signer_kid, signer_key.verifying_key());

    let release_directive = json!({
        "workload_id": "test-workload-release-01",
        "quorum_approval_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "quorum_count": 2,
        "nonce": "nonce_release_test_001"
    });

    let canonical_body = killswitch_telemetry::canonicalize_jcs(&release_directive).unwrap();
    let mut preimage = b"CAGE_QUARANTINE_RELEASE_V1:".to_vec();
    preimage.extend_from_slice(&canonical_body);

    let sig = signer_key.sign(&preimage);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    let req = Request::builder()
        .uri("/v1/cage/release")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-CAGE-Quarantine-Release", sig_b64)
        .header("X-CAGE-Signer-Kid", &signer_kid)
        .body(Body::from(canonical_body.clone()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = body_to_bytes(resp.into_body()).await;
    let receipt: CageQuarantineReleaseReceiptResponse = serde_json::from_slice(&body_bytes).unwrap();

    assert!(receipt.released);
    assert_eq!(receipt.enforcement_plane, "HOST_OS_KERNEL");
    assert_eq!(receipt.epoch_before, 1);
    assert_eq!(receipt.epoch_after, 2);
    assert_eq!(receipt.outcome, "RELEASED");
    assert_eq!(receipt.kid, state.ed25519_kid);

    // Verify lease was removed and epoch advanced
    assert_eq!(state.journal.unexpired_leases().len(), 0);
    assert_eq!(state.journal.get_generation_epoch("test-workload-release-01"), 2);

    // Verify receipt signature
    let unsigned_val = json!({
        "released": true,
        "enforcement_plane": "HOST_OS_KERNEL",
        "epoch_before": 1,
        "epoch_after": 2,
        "outcome": "RELEASED",
        "released_at": receipt.released_at,
        "kid": receipt.kid
    });
    let canonical_receipt = killswitch_telemetry::canonicalize_jcs(&unsigned_val).unwrap();
    let mut receipt_preimage = b"CAGE_QUARANTINE_RELEASE_RECEIPT_V1:".to_vec();
    receipt_preimage.extend_from_slice(&canonical_receipt);

    let sig_bytes = URL_SAFE_NO_PAD.decode(&receipt.signature).unwrap();
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    assert!(state.signing_key.verifying_key().verify(&receipt_preimage, &sig).is_ok());

    // Insufficient quorum count (< 2) rejected
    let bad_quorum = json!({
        "workload_id": "test-workload-release-01",
        "quorum_approval_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "quorum_count": 1,
        "nonce": "nonce_release_test_002"
    });
    let canonical_bad = killswitch_telemetry::canonicalize_jcs(&bad_quorum).unwrap();
    let mut bad_preimage = b"CAGE_QUARANTINE_RELEASE_V1:".to_vec();
    bad_preimage.extend_from_slice(&canonical_bad);
    let bad_sig = signer_key.sign(&bad_preimage);
    let bad_sig_b64 = URL_SAFE_NO_PAD.encode(bad_sig.to_bytes());

    let req_bad = Request::builder()
        .uri("/v1/cage/release")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-CAGE-Quarantine-Release", bad_sig_b64)
        .header("X-CAGE-Signer-Kid", &signer_kid)
        .body(Body::from(canonical_bad))
        .unwrap();

    let resp_bad = app.oneshot(req_bad).await.unwrap();
    assert_eq!(resp_bad.status(), StatusCode::BAD_REQUEST);
}
