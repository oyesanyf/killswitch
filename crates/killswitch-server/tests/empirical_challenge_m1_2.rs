//! Empirical Challenge Test Suite for Milestone M1 Challenger 2 (`crates/killswitch-server`)
//!
//! Adversarial stress testing for:
//! 1. `QuarantineJournal` Crash Safety & Recovery:
//!    - Atomic write-fsync-rename verification.
//!    - Corrupted / truncated journal file load-and-verify failure.
//!    - Trailing garbage bytes injection detection.
//!    - Cryptographic signature tampering rejection (Ed25519 seal).
//!    - Monotonic generation epoch advancement (`Gen N -> Gen N + 1`).
//!    - Unexpired vs expired lease lifecycle filtering.
//! 2. Quorum-Governed Quarantine Release (`POST /v1/cage/release`):
//!    - Exact quorum boundary enforcement (`quorum_count >= 2`).
//!    - `quorum_approval_digest` length (64 chars) and hex character validation.
//!    - Anti-replay nonce protection.
//!    - Monotonic epoch advancement in signed release receipt (`epoch_after > epoch_before`).

use std::sync::Arc;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use tempfile::tempdir;

use killswitch_core::killchain::HostContainmentManager;
use killswitch_server::journal::{QuarantineJournal, QuarantineLease};
use killswitch_server::routes::build_router;
use killswitch_server::server::ServerState;
use killswitch_server::types::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

async fn body_to_bytes(body: axum::body::Body) -> axum::body::Bytes {
    axum::body::to_bytes(body, usize::MAX).await.unwrap()
}

// ============================================================================
// SUITE 1: QuarantineJournal Crash Safety & Tamper Resistance
// ============================================================================

#[test]
fn test_journal_atomic_persistence_and_epoch_monotonicity() {
    let temp_dir = tempdir().unwrap();
    let signing_key = Arc::new(SigningKey::generate(&mut OsRng));
    let kid = "test_kid_m1_2_00000000000000000001".to_string();

    let journal = QuarantineJournal::new(
        temp_dir.path().to_path_buf(),
        Arc::clone(&signing_key),
        kid.clone(),
    );

    // Initial epoch must default to 1
    assert_eq!(journal.get_generation_epoch("workload-alpha"), 1);

    // Advance epoch 1 -> 2
    let (b1, a1) = journal.advance_generation_epoch("workload-alpha").unwrap();
    assert_eq!(b1, 1);
    assert_eq!(a1, 2);
    assert_eq!(journal.get_generation_epoch("workload-alpha"), 2);

    // Advance epoch 2 -> 3
    let (b2, a2) = journal.advance_generation_epoch("workload-alpha").unwrap();
    assert_eq!(b2, 2);
    assert_eq!(a2, 3);
    assert_eq!(journal.get_generation_epoch("workload-alpha"), 3);

    // Reopen journal in fresh instance from disk
    let journal_reopened = QuarantineJournal::new(
        temp_dir.path().to_path_buf(),
        Arc::clone(&signing_key),
        kid,
    );
    assert_eq!(journal_reopened.get_generation_epoch("workload-alpha"), 3);
}

#[test]
fn test_journal_detects_corrupted_trailing_bytes_and_truncation() {
    let temp_dir = tempdir().unwrap();
    let signing_key = Arc::new(SigningKey::generate(&mut OsRng));
    let kid = "test_kid_m1_2_00000000000000000002".to_string();

    let journal = QuarantineJournal::new(
        temp_dir.path().to_path_buf(),
        Arc::clone(&signing_key),
        kid.clone(),
    );

    let lease = QuarantineLease {
        workload_id: "victim-workload-01".to_string(),
        target_pid: Some(9999),
        trigger_reason: "ADVERSARIAL_SIMULATION".to_string(),
        rule_id: "RULE_SIM_001".to_string(),
        quarantined_at: Utc::now(),
        expires_at: None,
        nonce: "nonce_crash_001".to_string(),
    };
    journal.record_quarantine(lease).unwrap();

    let file_path = temp_dir.path().join("quarantine_journal.json");
    assert!(file_path.exists());
    let original_bytes = std::fs::read(&file_path).unwrap();

    // 1. Truncate journal file (simulate sudden power cut / crash during write)
    let truncated_bytes = &original_bytes[..original_bytes.len() / 2];
    std::fs::write(&file_path, truncated_bytes).unwrap();

    let journal_truncated = QuarantineJournal::new(
        temp_dir.path().to_path_buf(),
        Arc::clone(&signing_key),
        kid.clone(),
    );
    // When journal is truncated/corrupt, load_and_verify returns error and defaults to empty safe state
    let load_res = journal_truncated.load_and_verify();
    assert!(
        load_res.is_err(),
        "Truncated journal must fail load_and_verify() closed with error"
    );

    // 2. Trailing garbage bytes injection
    let mut corrupt_bytes = original_bytes.clone();
    corrupt_bytes.extend_from_slice(b"\n\x00\xFF\xDEADBEEFcorrupted_trailing_data");
    std::fs::write(&file_path, corrupt_bytes).unwrap();

    let journal_corrupt = QuarantineJournal::new(
        temp_dir.path().to_path_buf(),
        Arc::clone(&signing_key),
        kid,
    );
    assert!(
        journal_corrupt.load_and_verify().is_err(),
        "Journal with trailing garbage bytes must fail verification"
    );
}

#[test]
fn test_journal_detects_unauthorized_payload_tampering() {
    let temp_dir = tempdir().unwrap();
    let signing_key = Arc::new(SigningKey::generate(&mut OsRng));
    let kid = "test_kid_m1_2_00000000000000000003".to_string();

    let journal = QuarantineJournal::new(
        temp_dir.path().to_path_buf(),
        Arc::clone(&signing_key),
        kid.clone(),
    );

    let lease = QuarantineLease {
        workload_id: "agent-tamper-target".to_string(),
        target_pid: Some(5555),
        trigger_reason: "IMMUTABLE_LETHAL_DOSE".to_string(),
        rule_id: "CTRL_CBF_DOSE_001".to_string(),
        quarantined_at: Utc::now(),
        expires_at: None,
        nonce: "nonce_tamper_001".to_string(),
    };
    journal.record_quarantine(lease).unwrap();

    let file_path = temp_dir.path().join("quarantine_journal.json");
    let content = std::fs::read_to_string(&file_path).unwrap();

    // An attacker attempts to modify target_pid from 5555 to 1 without re-signing
    let tampered_content = content.replace("5555", "1");
    assert_ne!(content, tampered_content);
    std::fs::write(&file_path, tampered_content).unwrap();

    let journal_tampered = QuarantineJournal::new(
        temp_dir.path().to_path_buf(),
        Arc::clone(&signing_key),
        kid,
    );
    let verify_res = journal_tampered.load_and_verify();
    assert!(
        verify_res.is_err(),
        "Tampered journal payload must fail Ed25519 seal signature verification"
    );
    assert!(
        verify_res.unwrap_err().contains("verification failed"),
        "Error must specifically indicate seal signature verification failure"
    );
}

#[test]
fn test_journal_lease_expiration_filtering() {
    let temp_dir = tempdir().unwrap();
    let signing_key = Arc::new(SigningKey::generate(&mut OsRng));
    let kid = "test_kid_m1_2_00000000000000000004".to_string();

    let journal = QuarantineJournal::new(
        temp_dir.path().to_path_buf(),
        Arc::clone(&signing_key),
        kid,
    );

    // 1. Unexpired lease (no expiry)
    let lease_permanent = QuarantineLease {
        workload_id: "perm-workload".to_string(),
        target_pid: Some(101),
        trigger_reason: "PERMANENT_QUARANTINE".to_string(),
        rule_id: "RULE_PERM".to_string(),
        quarantined_at: Utc::now(),
        expires_at: None,
        nonce: "nonce_perm".to_string(),
    };
    journal.record_quarantine(lease_permanent).unwrap();

    // 2. Expired lease (expired 10 minutes ago)
    let lease_expired = QuarantineLease {
        workload_id: "expired-workload".to_string(),
        target_pid: Some(102),
        trigger_reason: "TEMP_QUARANTINE".to_string(),
        rule_id: "RULE_TEMP".to_string(),
        quarantined_at: Utc::now() - Duration::minutes(20),
        expires_at: Some(Utc::now() - Duration::minutes(10)),
        nonce: "nonce_expired".to_string(),
    };
    journal.record_quarantine(lease_expired).unwrap();

    let unexpired = journal.unexpired_leases();
    assert_eq!(unexpired.len(), 1, "Only unexpired leases must be returned");
    assert_eq!(unexpired[0].workload_id, "perm-workload");
}

// ============================================================================
// SUITE 2: Quorum-Governed Quarantine Release Endpoint Verification
// ============================================================================

fn setup_cage_server_state() -> (Arc<ServerState>, Arc<SigningKey>, String) {
    let temp_dir = tempdir().unwrap();
    let containment = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path())).unwrap());
    let state = Arc::new(ServerState::with_defaults(containment));

    // Register a valid test signing key into CAGE key manifest
    let mut rng = OsRng;
    let client_signing_key = Arc::new(SigningKey::generate(&mut rng));
    let client_kid = "cage-client-test-kid-0123456789abcdef".to_string();
    state
        .cage_key_manifest
        .register_key(&client_kid, client_signing_key.verifying_key());

    (state, client_signing_key, client_kid)
}

#[tokio::test]
async fn test_cage_release_insufficient_quorum_rejected() {
    let (state, client_key, client_kid) = setup_cage_server_state();
    let app = build_router(state);

    // 1. Quorum count = 0 (must be rejected)
    let body_q0 = serde_json::json!({
        "workload_id": "test-workload",
        "quorum_count": 0,
        "quorum_approval_digest": "4b42b102b4d4b1a457c0e5a8f4c2c77f02d0cf3b1b6cf7f8e3f94a5e01b34a12",
        "release_reason": "Operator approval",
        "nonce": "nonce-q0-001"
    });

    let canonical_q0 = killswitch_telemetry::canonicalize_jcs(&body_q0).unwrap();
    let mut preimage_q0 = b"CAGE_QUARANTINE_RELEASE_V1:".to_vec();
    preimage_q0.extend_from_slice(&canonical_q0);
    let sig_q0 = URL_SAFE_NO_PAD.encode(client_key.sign(&preimage_q0).to_bytes());

    let req_q0 = Request::builder()
        .uri("/v1/cage/release")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-CAGE-Quarantine-Release", sig_q0)
        .header("X-CAGE-Signer-Kid", &client_kid)
        .body(Body::from(serde_json::to_vec(&body_q0).unwrap()))
        .unwrap();

    let resp_q0 = app.clone().oneshot(req_q0).await.unwrap();
    assert_eq!(
        resp_q0.status(),
        StatusCode::BAD_REQUEST,
        "quorum_count = 0 must be rejected with 400 Bad Request"
    );

    // 2. Quorum count = 1 (must be rejected, CAGE invariant requires quorum >= 2)
    let body_q1 = serde_json::json!({
        "workload_id": "test-workload",
        "quorum_count": 1,
        "quorum_approval_digest": "4b42b102b4d4b1a457c0e5a8f4c2c77f02d0cf3b1b6cf7f8e3f94a5e01b34a12",
        "release_reason": "Single operator approval",
        "nonce": "nonce-q1-002"
    });

    let canonical_q1 = killswitch_telemetry::canonicalize_jcs(&body_q1).unwrap();
    let mut preimage_q1 = b"CAGE_QUARANTINE_RELEASE_V1:".to_vec();
    preimage_q1.extend_from_slice(&canonical_q1);
    let sig_q1 = URL_SAFE_NO_PAD.encode(client_key.sign(&preimage_q1).to_bytes());

    let req_q1 = Request::builder()
        .uri("/v1/cage/release")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-CAGE-Quarantine-Release", sig_q1)
        .header("X-CAGE-Signer-Kid", &client_kid)
        .body(Body::from(serde_json::to_vec(&body_q1).unwrap()))
        .unwrap();

    let resp_q1 = app.clone().oneshot(req_q1).await.unwrap();
    assert_eq!(
        resp_q1.status(),
        StatusCode::BAD_REQUEST,
        "quorum_count = 1 must be rejected with 400 Bad Request"
    );
}

#[tokio::test]
async fn test_cage_release_malformed_quorum_approval_digest_rejected() {
    let (state, client_key, client_kid) = setup_cage_server_state();
    let app = build_router(state);

    // 1. Digest too short (63 chars)
    let body_short = serde_json::json!({
        "workload_id": "test-workload",
        "quorum_count": 2,
        "quorum_approval_digest": "4b42b102b4d4b1a457c0e5a8f4c2c77f02d0cf3b1b6cf7f8e3f94a5e01b34a1", // 63 chars
        "release_reason": "Valid quorum",
        "nonce": "nonce-digest-001"
    });

    let canonical_short = killswitch_telemetry::canonicalize_jcs(&body_short).unwrap();
    let mut preimage_short = b"CAGE_QUARANTINE_RELEASE_V1:".to_vec();
    preimage_short.extend_from_slice(&canonical_short);
    let sig_short = URL_SAFE_NO_PAD.encode(client_key.sign(&preimage_short).to_bytes());

    let req_short = Request::builder()
        .uri("/v1/cage/release")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-CAGE-Quarantine-Release", sig_short)
        .header("X-CAGE-Signer-Kid", &client_kid)
        .body(Body::from(serde_json::to_vec(&body_short).unwrap()))
        .unwrap();

    let resp_short = app.clone().oneshot(req_short).await.unwrap();
    assert_eq!(resp_short.status(), StatusCode::BAD_REQUEST);

    // 2. Non-hex characters (contains 'Z' and 'G')
    let body_non_hex = serde_json::json!({
        "workload_id": "test-workload",
        "quorum_count": 2,
        "quorum_approval_digest": "ZZZZb102b4d4b1a457c0e5a8f4c2c77f02d0cf3b1b6cf7f8e3f94a5e01b34aGG",
        "release_reason": "Valid quorum",
        "nonce": "nonce-digest-002"
    });

    let canonical_non_hex = killswitch_telemetry::canonicalize_jcs(&body_non_hex).unwrap();
    let mut preimage_non_hex = b"CAGE_QUARANTINE_RELEASE_V1:".to_vec();
    preimage_non_hex.extend_from_slice(&canonical_non_hex);
    let sig_non_hex = URL_SAFE_NO_PAD.encode(client_key.sign(&preimage_non_hex).to_bytes());

    let req_non_hex = Request::builder()
        .uri("/v1/cage/release")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-CAGE-Quarantine-Release", sig_non_hex)
        .header("X-CAGE-Signer-Kid", &client_kid)
        .body(Body::from(serde_json::to_vec(&body_non_hex).unwrap()))
        .unwrap();

    let resp_non_hex = app.clone().oneshot(req_non_hex).await.unwrap();
    assert_eq!(resp_non_hex.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_cage_release_valid_quorum_and_anti_replay() {
    let (state, client_key, client_kid) = setup_cage_server_state();
    let app = build_router(state);

    let workload = "isolated-workload-42";
    let valid_body = serde_json::json!({
        "workload_id": workload,
        "quorum_count": 2,
        "quorum_approval_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "release_reason": "Two-operator safety council sign-off",
        "nonce": "nonce-valid-replay-001"
    });

    let canonical = killswitch_telemetry::canonicalize_jcs(&valid_body).unwrap();
    let mut preimage = b"CAGE_QUARANTINE_RELEASE_V1:".to_vec();
    preimage.extend_from_slice(&canonical);
    let sig = URL_SAFE_NO_PAD.encode(client_key.sign(&preimage).to_bytes());

    let req1 = Request::builder()
        .uri("/v1/cage/release")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-CAGE-Quarantine-Release", &sig)
        .header("X-CAGE-Signer-Kid", &client_kid)
        .body(Body::from(serde_json::to_vec(&valid_body).unwrap()))
        .unwrap();

    let resp1 = app.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK, "Valid quorum release must succeed with 200 OK");

    let body_bytes = body_to_bytes(resp1.into_body()).await;
    let receipt: CageQuarantineReleaseReceiptResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert!(receipt.released);
    assert_eq!(receipt.enforcement_plane, "HOST_OS_KERNEL");
    assert_eq!(receipt.epoch_before, 1);
    assert_eq!(receipt.epoch_after, 2);
    assert!(receipt.epoch_after > receipt.epoch_before);

    // 2. Replay attack: submitting the exact same request with identical nonce must fail
    let req2 = Request::builder()
        .uri("/v1/cage/release")
        .method("POST")
        .header("Content-Type", "application/json")
        .header("X-CAGE-Quarantine-Release", &sig)
        .header("X-CAGE-Signer-Kid", &client_kid)
        .body(Body::from(serde_json::to_vec(&valid_body).unwrap()))
        .unwrap();

    let resp2 = app.oneshot(req2).await.unwrap();
    assert_eq!(
        resp2.status(),
        StatusCode::CONFLICT,
        "Replay attack with reused nonce must be rejected with 409 Conflict"
    );
}
