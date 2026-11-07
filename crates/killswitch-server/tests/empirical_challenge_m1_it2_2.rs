//! Empirical Challenge Test Suite for Milestone M1 Iteration 2 Challenger 2 (`crates/killswitch-server`)
//!
//! Adversarial stress testing for:
//! 1. Conformal Validation & Multi-Voter Adjudication Adversarial Test:
//!    - Attack `POST /v1/cage/conformal/validate`:
//!      - Benign scalar and multi-dimensional feature vectors -> genuine non-trivial p-values (> alpha), CONSENSUS_ALLOW.
//!      - Extreme anomaly scalar and high-dimensional vectors -> p-value approaches 0.0 (<= 1/(n_k+1)), CONSENSUS_DENY.
//!      - Continuous inputs -> assert non-dummy, mathematically distinct outputs (never hardcoded 0.85, 0.50...).
//!      - Cryptographic Ed25519 verification over JCS canonical preimage and replay protection.
//! 2. QuarantineJournal Monotonicity & Tamper Detection Adversarial Test:
//!    - Strictly monotonic sequence numbering (`seq: 1, 2, 3...`).
//!    - SHA-256 previous-hash chaining (`prev_hash` == predecessor `record_hash`).
//!    - On-disk intermediate record mutations (action, payload digest, prev_hash, seq, deletion, reordering).
//!    - Assertion that `verify_hash_chain()` fails closed and pinpoints tampering.
//!    - Sealed envelope Ed25519 signature tamper detection via `load_and_verify()`.
//! 3. Trace Conformance Verification across all 8 tiers + ALLOW via `scripts/check_trace_conformance.py`.

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use rand::rngs::OsRng;
use serde_json::json;
use std::sync::Arc;
use tempfile::tempdir;
use tower::ServiceExt;

use killswitch_core::killchain::HostContainmentManager;
use killswitch_server::journal::{QuarantineJournal, QuarantineLease, SealedJournalEnvelope};
use killswitch_server::routes::build_router;
use killswitch_server::server::ServerState;
use killswitch_server::types::*;
use killswitch_telemetry::cage_governance::{
    export_cage_governance_trace_v1, CageDecisionReceipt, CageEvaluationRequest,
    CageEvaluationResponse, CageTier, CageVerdict,
};

async fn body_to_bytes(body: axum::body::Body) -> axum::body::Bytes {
    axum::body::to_bytes(body, usize::MAX).await.unwrap()
}

fn setup_test_server_state() -> Arc<ServerState> {
    std::env::set_var(
        "KILLSWITCH_MASTER_TOKEN",
        "test_master_token_0123456789abcdef0123456789abcdef",
    );
    let temp_dir = tempdir().unwrap();
    let containment =
        Arc::new(HostContainmentManager::new_simulated(Some(temp_dir.path())).unwrap());
    Arc::new(ServerState::with_defaults(containment))
}

// ============================================================================
// SUITE 1: Conformal Validation & Multi-Voter Adjudication Adversarial Tests
// ============================================================================

#[tokio::test]
async fn test_adversarial_conformal_benign_vectors_produce_nontrivial_pvalues() {
    let state = setup_test_server_state();
    let app = build_router(Arc::clone(&state));

    // Vector 1: Near-zero scalar nonconformity score
    let req_scalar_benign = json!({
        "scores": [0.05],
        "alpha": 0.05,
        "action": "benign_read_telemetry",
        "nonce": "adv_conf_nonce_001"
    });

    let req = Request::builder()
        .uri("/v1/cage/conformal/validate")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_scalar_benign).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_bytes(resp.into_body()).await;
    let val_resp: CageConformalValidateResponse = serde_json::from_slice(&body).unwrap();

    assert!(
        val_resp.admitted,
        "Benign scalar score 0.05 must be admitted"
    );
    assert!(
        val_resp.p_value > 0.05,
        "P-value must exceed alpha=0.05, got {}",
        val_resp.p_value
    );
    assert_eq!(val_resp.voter_consensus, "CONSENSUS_ALLOW");

    // Vector 2: Conforming scalar score 0.5
    let req_scalar_05 = json!({
        "scores": [0.5],
        "alpha": 0.05,
        "action": "benign_audit_query",
        "nonce": "adv_conf_nonce_002"
    });

    let req2 = Request::builder()
        .uri("/v1/cage/conformal/validate")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_scalar_05).unwrap()))
        .unwrap();

    let resp2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2 = body_to_bytes(resp2.into_body()).await;
    let val_resp2: CageConformalValidateResponse = serde_json::from_slice(&body2).unwrap();

    assert!(val_resp2.admitted, "Conforming score 0.5 must be admitted");
    assert!(
        val_resp2.p_value > 0.05,
        "P-value must exceed alpha, got {}",
        val_resp2.p_value
    );
    assert_eq!(val_resp2.voter_consensus, "CONSENSUS_ALLOW");

    // Vector 3: Multi-dimensional benign representation vector at calibrated centroid
    let req_vec_benign = json!({
        "scores": [0.625, 0.75, 0.875, 0.25],
        "alpha": 0.05,
        "action": "benign_multivariate_query",
        "nonce": "adv_conf_nonce_003"
    });

    let req3 = Request::builder()
        .uri("/v1/cage/conformal/validate")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_vec_benign).unwrap()))
        .unwrap();

    let resp3 = app.oneshot(req3).await.unwrap();
    assert_eq!(resp3.status(), StatusCode::OK);
    let body3 = body_to_bytes(resp3.into_body()).await;
    let val_resp3: CageConformalValidateResponse = serde_json::from_slice(&body3).unwrap();

    assert!(
        val_resp3.admitted,
        "Calibrated multivariate vector must be admitted"
    );
    assert!(
        val_resp3.p_value > 0.05,
        "Multivariate benign p-value must exceed alpha=0.05, got {}",
        val_resp3.p_value
    );
    assert_eq!(val_resp3.voter_consensus, "CONSENSUS_ALLOW");
}

#[tokio::test]
async fn test_adversarial_conformal_extreme_anomalies_drive_pvalue_to_zero_and_deny() {
    let state = setup_test_server_state();
    let app = build_router(Arc::clone(&state));

    // Attack Vector 1: Massive scalar nonconformity score (score = 500.0)
    let req_scalar_extreme = json!({
        "scores": [500.0],
        "alpha": 0.05,
        "action": "privilege_escalation_kernel_overwrite",
        "nonce": "adv_anomaly_nonce_001"
    });

    let req1 = Request::builder()
        .uri("/v1/cage/conformal/validate")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_scalar_extreme).unwrap()))
        .unwrap();

    let resp1 = app.clone().oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let body1 = body_to_bytes(resp1.into_body()).await;
    let val_resp1: CageConformalValidateResponse = serde_json::from_slice(&body1).unwrap();

    assert!(!val_resp1.admitted, "Score 500.0 must be denied");
    // Under 100 calibration samples, min non-zero p-value is 1/101 ~= 0.0099
    assert!(
        val_resp1.p_value <= 0.01,
        "Extreme anomaly p-value must approach 0.0 (<= 0.01), got {}",
        val_resp1.p_value
    );
    assert_eq!(val_resp1.voter_consensus, "CONSENSUS_DENY");

    // Attack Vector 2: Massive multi-dimensional anomaly vector ([1000.0, -500.0, 2000.0, 750.0])
    let req_vec_extreme = json!({
        "scores": [1000.0, -500.0, 2000.0, 750.0],
        "alpha": 0.05,
        "action": "byzantine_memory_injection",
        "nonce": "adv_anomaly_nonce_002"
    });

    let req2 = Request::builder()
        .uri("/v1/cage/conformal/validate")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_vec_extreme).unwrap()))
        .unwrap();

    let resp2 = app.clone().oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2 = body_to_bytes(resp2.into_body()).await;
    let val_resp2: CageConformalValidateResponse = serde_json::from_slice(&body2).unwrap();

    assert!(!val_resp2.admitted, "Extreme vector must be rejected");
    assert!(
        val_resp2.p_value <= 0.01,
        "Vector anomaly p-value must approach 0.0, got {}",
        val_resp2.p_value
    );
    assert_eq!(val_resp2.voter_consensus, "CONSENSUS_DENY");

    // Attack Vector 3: Single-dimension spike anomaly ([0.0, 10000.0, 0.0, 0.0])
    let req_vec_spike = json!({
        "scores": [0.0, 10000.0, 0.0, 0.0],
        "alpha": 0.05,
        "action": "adversarial_token_suffix_gcg",
        "nonce": "adv_anomaly_nonce_003"
    });

    let req3 = Request::builder()
        .uri("/v1/cage/conformal/validate")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_vec_spike).unwrap()))
        .unwrap();

    let resp3 = app.oneshot(req3).await.unwrap();
    assert_eq!(resp3.status(), StatusCode::OK);
    let body3 = body_to_bytes(resp3.into_body()).await;
    let val_resp3: CageConformalValidateResponse = serde_json::from_slice(&body3).unwrap();

    assert!(!val_resp3.admitted);
    assert!(val_resp3.p_value <= 0.01);
    assert_eq!(val_resp3.voter_consensus, "CONSENSUS_DENY");
}

#[tokio::test]
async fn test_adversarial_conformal_responses_are_not_hardcoded_dummy_constants() {
    let state = setup_test_server_state();
    let app = build_router(Arc::clone(&state));

    // The legacy dummy implementation returned static staircase constants:
    // [0.85, 0.50, 0.20, 0.02, 0.001]
    let legacy_dummy_constants = [0.85, 0.50, 0.20, 0.02, 0.001];

    // Probe across a spectrum of diverse scores
    let test_scores = [0.15, 0.35, 0.85, 1.45, 2.75, 4.25, 7.50, 12.0];
    let mut observed_p_values = Vec::new();

    for (idx, &score) in test_scores.iter().enumerate() {
        let req_body = json!({
            "scores": [score],
            "alpha": 0.05,
            "action": format!("test_probe_action_{}", idx),
            "nonce": format!("adv_dummy_probe_{}", idx)
        });

        let req = Request::builder()
            .uri("/v1/cage/conformal/validate")
            .method("POST")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_to_bytes(resp.into_body()).await;
        let val_resp: CageConformalValidateResponse = serde_json::from_slice(&body).unwrap();

        // 1. Assert response p_value is NEVER one of the legacy dummy staircase constants
        for &dummy in &legacy_dummy_constants {
            assert!(
                (val_resp.p_value - dummy).abs() > 1e-4,
                "Observed p_value {} matched legacy hardcoded constant {}",
                val_resp.p_value,
                dummy
            );
        }

        observed_p_values.push(val_resp.p_value);
    }

    // 2. Assert p-values are monotonically decreasing as nonconformity scores increase
    for i in 0..(observed_p_values.len() - 1) {
        assert!(
            observed_p_values[i] >= observed_p_values[i + 1],
            "P-values must decrease monotonically with score: p[{}]={} vs p[{}]={}",
            i,
            observed_p_values[i],
            i + 1,
            observed_p_values[i + 1]
        );
    }

    // 3. Assert outputs are mathematically distinct across the test spectrum
    let distinct_count = observed_p_values
        .iter()
        .map(|p| (*p * 1000.0).round() as i64)
        .collect::<std::collections::HashSet<_>>()
        .len();
    assert!(
        distinct_count >= 5,
        "Expected at least 5 distinct mathematical p-value quantiles across spectrum, got {}",
        distinct_count
    );
}

#[tokio::test]
async fn test_adversarial_conformal_signature_verification_and_replay_attack() {
    let state = setup_test_server_state();
    let app = build_router(Arc::clone(&state));

    let req_body = json!({
        "scores": [0.42],
        "alpha": 0.05,
        "action": "adversarial_replay_probe",
        "nonce": "adv_replay_unique_nonce_12345"
    });

    let req = Request::builder()
        .uri("/v1/cage/conformal/validate")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_bytes(resp.into_body()).await;
    let val_resp: CageConformalValidateResponse = serde_json::from_slice(&body).unwrap();

    // Verify Ed25519 signature
    let unsigned_val = json!({
        "admitted": val_resp.admitted,
        "p_value": val_resp.p_value,
        "alpha": val_resp.alpha,
        "voter_consensus": val_resp.voter_consensus,
        "timestamp_utc": val_resp.timestamp_utc,
        "envelope_digest": val_resp.envelope_digest,
        "kid": val_resp.kid
    });
    let canonical = killswitch_telemetry::canonicalize_jcs(&unsigned_val).unwrap();
    let mut preimage = b"CAGE_CONFORMAL_VALIDATION_V1:".to_vec();
    preimage.extend_from_slice(&canonical);

    let sig_bytes = URL_SAFE_NO_PAD.decode(&val_resp.signature).unwrap();
    assert_eq!(sig_bytes.len(), 64);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    assert!(
        state
            .signing_key
            .verifying_key()
            .verify(&preimage, &sig)
            .is_ok(),
        "Conformal validation response signature must cryptographically verify"
    );

    // Replay attack: submitting exact same request with duplicate nonce must be rejected
    let req_replay = Request::builder()
        .uri("/v1/cage/conformal/validate")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
        .unwrap();

    let resp_replay = app.oneshot(req_replay).await.unwrap();
    assert_eq!(
        resp_replay.status(),
        StatusCode::CONFLICT,
        "Duplicate nonce replay must return 409 Conflict"
    );
}

// ============================================================================
// SUITE 2: QuarantineJournal Monotonicity & Tamper Detection Adversarial Tests
// ============================================================================

#[test]
fn test_journal_monotonic_sequence_numbers_and_hash_chaining() {
    let temp_dir = tempdir().unwrap();
    let signing_key = Arc::new(SigningKey::generate(&mut OsRng));
    let kid = "test_kid_m1_it2_2_journal_001".to_string();

    let journal = QuarantineJournal::new(
        temp_dir.path().to_path_buf(),
        Arc::clone(&signing_key),
        kid.clone(),
    );

    // Initial state invariants
    assert_eq!(journal.current_seq(), 0);
    assert_eq!(journal.latest_prev_hash(), "");

    // Operation 1: Advance epoch
    let (b1, a1) = journal.advance_generation_epoch("workload-alpha").unwrap();
    assert_eq!(b1, 1);
    assert_eq!(a1, 2);
    assert_eq!(journal.current_seq(), 1);
    let hash_1 = journal.latest_prev_hash();
    assert!(!hash_1.is_empty());

    // Operation 2: Record quarantine lease
    let lease1 = QuarantineLease {
        workload_id: "workload-alpha".to_string(),
        target_pid: Some(1001),
        trigger_reason: "CBF_CRITICAL_VIOLATION".to_string(),
        rule_id: "RULE_LETHAL_001".to_string(),
        quarantined_at: Utc::now(),
        expires_at: None,
        nonce: "nonce_journal_op_2".to_string(),
    };
    journal.record_quarantine(lease1).unwrap();
    assert_eq!(journal.current_seq(), 2);
    let hash_2 = journal.latest_prev_hash();
    assert!(!hash_2.is_empty());
    assert_ne!(hash_1, hash_2);

    // Operation 3: Advance epoch on another workload
    journal.advance_generation_epoch("workload-beta").unwrap();
    assert_eq!(journal.current_seq(), 3);
    let hash_3 = journal.latest_prev_hash();

    // Operation 4: Release quarantine on workload-alpha
    journal.release_quarantine("workload-alpha").unwrap();
    assert_eq!(journal.current_seq(), 4);
    let hash_4 = journal.latest_prev_hash();

    // Operation 5: Record quarantine on workload-beta
    let lease2 = QuarantineLease {
        workload_id: "workload-beta".to_string(),
        target_pid: Some(1002),
        trigger_reason: "TAINT_DLP_EGRESS_EXFIL".to_string(),
        rule_id: "RULE_DLP_002".to_string(),
        quarantined_at: Utc::now(),
        expires_at: None,
        nonce: "nonce_journal_op_5".to_string(),
    };
    journal.record_quarantine(lease2).unwrap();
    assert_eq!(journal.current_seq(), 5);
    let hash_5 = journal.latest_prev_hash();

    // Inspect records vector directly
    let records = journal.records();
    assert_eq!(records.len(), 5);

    // Verify strict sequence monotonicity (1, 2, 3, 4, 5)
    for (idx, rec) in records.iter().enumerate() {
        assert_eq!(
            rec.seq,
            (idx as u64) + 1,
            "Record at index {} must have monotonic seq {}",
            idx,
            idx + 1
        );
    }

    // Verify hash chain links
    assert_eq!(records[0].prev_hash, "");
    assert_eq!(records[0].record_hash, hash_1);
    assert_eq!(records[1].prev_hash, records[0].record_hash);
    assert_eq!(records[1].record_hash, hash_2);
    assert_eq!(records[2].prev_hash, records[1].record_hash);
    assert_eq!(records[2].record_hash, hash_3);
    assert_eq!(records[3].prev_hash, records[2].record_hash);
    assert_eq!(records[3].record_hash, hash_4);
    assert_eq!(records[4].prev_hash, records[3].record_hash);
    assert_eq!(records[4].record_hash, hash_5);

    // Verify entire hash chain passes cryptographic audit
    assert!(journal.verify_hash_chain().unwrap());
}

#[test]
fn test_journal_tamper_detection_intermediate_record_mutations() {
    let temp_dir = tempdir().unwrap();
    let signing_key = Arc::new(SigningKey::generate(&mut OsRng));
    let kid = "test_kid_m1_it2_2_journal_tamper".to_string();

    let journal = QuarantineJournal::new(
        temp_dir.path().to_path_buf(),
        Arc::clone(&signing_key),
        kid.clone(),
    );

    // Populate 4 records
    journal.advance_generation_epoch("agent-x").unwrap(); // seq 1
    let lease1 = QuarantineLease {
        workload_id: "agent-x".to_string(),
        target_pid: Some(4001),
        trigger_reason: "ANOMALY_1".to_string(),
        rule_id: "RULE_1".to_string(),
        quarantined_at: Utc::now(),
        expires_at: None,
        nonce: "tamper_n_1".to_string(),
    };
    journal.record_quarantine(lease1).unwrap(); // seq 2
    journal.advance_generation_epoch("agent-y").unwrap(); // seq 3
    journal.release_quarantine("agent-x").unwrap(); // seq 4

    assert!(journal.verify_hash_chain().unwrap());

    let journal_file = temp_dir.path().join("quarantine_journal.json");
    assert!(journal_file.exists());
    let original_json = std::fs::read_to_string(&journal_file).unwrap();

    // -------------------------------------------------------------------------
    // Attack Vector 1: Mutate `action` in intermediate record 2 (change QUARANTINE to NOP)
    // -------------------------------------------------------------------------
    {
        let mut parsed: serde_json::Value = serde_json::from_str(&original_json).unwrap();
        parsed["payload"]["records"][1]["action"] = json!("NOP_ACTION");
        std::fs::write(
            &journal_file,
            serde_json::to_string_pretty(&parsed).unwrap(),
        )
        .unwrap();

        let reopened = QuarantineJournal::new(
            temp_dir.path().to_path_buf(),
            Arc::clone(&signing_key),
            kid.clone(),
        );
        // The file cannot be loaded because envelope signature is invalid
        assert!(reopened.load_and_verify().is_err());
    }

    // -------------------------------------------------------------------------
    // Attack Vector 2: Re-sign envelope after mutating record 2 to test `verify_hash_chain()`
    // An attacker with legitimate signing key (or inside actor) alters an entry
    // but fails to defeat the cryptographic SHA-256 hash chaining.
    // -------------------------------------------------------------------------
    {
        let mut envelope: SealedJournalEnvelope = serde_json::from_str(&original_json).unwrap();
        // Mutate record 2 payload_digest
        envelope.payload.records[1].payload_digest = "tampered_digest_9999999999999999".to_string();

        // Re-sign envelope with the key
        let payload_val = serde_json::to_value(&envelope.payload).unwrap();
        let canonical = killswitch_telemetry::canonicalize_jcs(&payload_val).unwrap();
        let mut preimage = b"CAGE_JOURNAL_SEAL_V1:".to_vec();
        preimage.extend_from_slice(&canonical);
        let sig = signing_key.sign(&preimage);
        envelope.signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        std::fs::write(
            &journal_file,
            serde_json::to_string_pretty(&envelope).unwrap(),
        )
        .unwrap();

        let reopened = QuarantineJournal::new(
            temp_dir.path().to_path_buf(),
            Arc::clone(&signing_key),
            kid.clone(),
        );
        // Envelope seal is cryptographically valid, but hash chain MUST fail!
        let chain_res = reopened.verify_hash_chain();
        assert!(
            chain_res.is_err(),
            "verify_hash_chain must detect mutated payload_digest"
        );
        let err_msg = chain_res.unwrap_err();
        assert!(
            err_msg.contains("Record hash mismatch at seq 2"),
            "Error must specify record hash mismatch at seq 2, got '{}'",
            err_msg
        );
    }

    // -------------------------------------------------------------------------
    // Attack Vector 3: Mutate `prev_hash` of record 3
    // -------------------------------------------------------------------------
    {
        let mut envelope: SealedJournalEnvelope = serde_json::from_str(&original_json).unwrap();
        envelope.payload.records[2].prev_hash =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();

        let payload_val = serde_json::to_value(&envelope.payload).unwrap();
        let canonical = killswitch_telemetry::canonicalize_jcs(&payload_val).unwrap();
        let mut preimage = b"CAGE_JOURNAL_SEAL_V1:".to_vec();
        preimage.extend_from_slice(&canonical);
        let sig = signing_key.sign(&preimage);
        envelope.signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        std::fs::write(
            &journal_file,
            serde_json::to_string_pretty(&envelope).unwrap(),
        )
        .unwrap();

        let reopened = QuarantineJournal::new(
            temp_dir.path().to_path_buf(),
            Arc::clone(&signing_key),
            kid.clone(),
        );
        let chain_res = reopened.verify_hash_chain();
        assert!(
            chain_res.is_err(),
            "verify_hash_chain must detect broken prev_hash"
        );
        let err_msg = chain_res.unwrap_err();
        assert!(
            err_msg.contains("Prev hash chain broken at seq 3"),
            "Error must specify prev hash chain broken at seq 3, got '{}'",
            err_msg
        );
    }

    // -------------------------------------------------------------------------
    // Attack Vector 4: Non-monotonic sequence injection (duplicate seq: record 3 set to seq 2)
    // -------------------------------------------------------------------------
    {
        let mut envelope: SealedJournalEnvelope = serde_json::from_str(&original_json).unwrap();
        envelope.payload.records[2].seq = 2; // Seq becomes [1, 2, 2, 4]

        let payload_val = serde_json::to_value(&envelope.payload).unwrap();
        let canonical = killswitch_telemetry::canonicalize_jcs(&payload_val).unwrap();
        let mut preimage = b"CAGE_JOURNAL_SEAL_V1:".to_vec();
        preimage.extend_from_slice(&canonical);
        let sig = signing_key.sign(&preimage);
        envelope.signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        std::fs::write(
            &journal_file,
            serde_json::to_string_pretty(&envelope).unwrap(),
        )
        .unwrap();

        let reopened = QuarantineJournal::new(
            temp_dir.path().to_path_buf(),
            Arc::clone(&signing_key),
            kid.clone(),
        );
        let chain_res = reopened.verify_hash_chain();
        assert!(
            chain_res.is_err(),
            "verify_hash_chain must detect non-monotonic sequence"
        );
        let err_msg = chain_res.unwrap_err();
        assert!(
            err_msg.contains("Monotonic sequence broken at index 2"),
            "Error must specify monotonic sequence broken, got '{}'",
            err_msg
        );
    }

    // -------------------------------------------------------------------------
    // Attack Vector 5: Intermediate record deletion (remove record 2, leaving records 1, 3, 4)
    // -------------------------------------------------------------------------
    {
        let mut envelope: SealedJournalEnvelope = serde_json::from_str(&original_json).unwrap();
        envelope.payload.records.remove(1); // Delete record 2

        let payload_val = serde_json::to_value(&envelope.payload).unwrap();
        let canonical = killswitch_telemetry::canonicalize_jcs(&payload_val).unwrap();
        let mut preimage = b"CAGE_JOURNAL_SEAL_V1:".to_vec();
        preimage.extend_from_slice(&canonical);
        let sig = signing_key.sign(&preimage);
        envelope.signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        std::fs::write(
            &journal_file,
            serde_json::to_string_pretty(&envelope).unwrap(),
        )
        .unwrap();

        let reopened = QuarantineJournal::new(
            temp_dir.path().to_path_buf(),
            Arc::clone(&signing_key),
            kid.clone(),
        );
        let chain_res = reopened.verify_hash_chain();
        assert!(
            chain_res.is_err(),
            "Deleted record must break sequence / hash chain"
        );
        let err_msg = chain_res.unwrap_err();
        assert!(
            err_msg.contains("Monotonic sequence broken at index 1")
                || err_msg.contains("Prev hash chain broken"),
            "Error must catch omission, got '{}'",
            err_msg
        );
    }

    // -------------------------------------------------------------------------
    // Attack Vector 6: Record reordering / swap (swap record 1 and record 2)
    // -------------------------------------------------------------------------
    {
        let mut envelope: SealedJournalEnvelope = serde_json::from_str(&original_json).unwrap();
        envelope.payload.records.swap(1, 2);

        let payload_val = serde_json::to_value(&envelope.payload).unwrap();
        let canonical = killswitch_telemetry::canonicalize_jcs(&payload_val).unwrap();
        let mut preimage = b"CAGE_JOURNAL_SEAL_V1:".to_vec();
        preimage.extend_from_slice(&canonical);
        let sig = signing_key.sign(&preimage);
        envelope.signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        std::fs::write(
            &journal_file,
            serde_json::to_string_pretty(&envelope).unwrap(),
        )
        .unwrap();

        let reopened =
            QuarantineJournal::new(temp_dir.path().to_path_buf(), Arc::clone(&signing_key), kid);
        let chain_res = reopened.verify_hash_chain();
        assert!(chain_res.is_err(), "Reordered records must fail hash chain");
    }
}

// ============================================================================
// SUITE 3: Formal CAGE Trace Conformance Verification across all 8 Tiers + ALLOW
// ============================================================================

#[test]
fn test_governance_trace_conformance_all_eight_tiers_and_allow() {
    let dummy_req = CageEvaluationRequest {
        agent_id: "spiffe://cage.local/test-agent".to_string(),
        role: "FinancialAuditor".to_string(),
        tool_name: "query_balance".to_string(),
        arguments: json!({}),
        confidence_score: Some(0.95),
        amount_usd: Some(10.0),
        dose_mg: None,
        warrant_token: None,
        human_approval: None,
        context: None,
    };

    let secret_key = [1u8; 32];
    let receipt_allow = CageDecisionReceipt::create_and_sign(
        "spiffe://cage.local/test-agent",
        "query_balance",
        "arg-digest-001",
        "sub-digest-001",
        CageVerdict::Allow,
        CageTier::Tier8Fiscal,
        "RULE_ALLOW_001",
        vec!["Passed all gates".to_string()],
        None,
        1700000000000,
        &secret_key,
    );

    // 1. ALLOW -> produces SEAL_ISSUED + EXECUTED
    let resp_allow = CageEvaluationResponse {
        verdict: CageVerdict::Allow,
        rule_id: "RULE_ALLOW_001".to_string(),
        tier: CageTier::Tier8Fiscal,
        receipt: receipt_allow,
        governance_trace: Vec::new(),
        error_message: None,
    };

    let mut trace_events = export_cage_governance_trace_v1(&dummy_req, &resp_allow);
    assert_eq!(
        trace_events.len(),
        2,
        "ALLOW must emit SEAL_ISSUED and EXECUTED events"
    );
    assert_eq!(trace_events[0]["phase"], "SEAL_ISSUED");
    assert_eq!(trace_events[0]["verdict"], "ALLOW");
    assert_eq!(trace_events[0]["seal_present"], true);
    assert_eq!(trace_events[1]["phase"], "EXECUTED");

    // 2. All 8 refusal tiers
    let refusal_tiers = [
        (CageTier::Tier1Ftra, 1),
        (CageTier::Tier2Stpa, 2),
        (CageTier::Tier3Opa, 3),
        (CageTier::Tier4Confidence, 4),
        (CageTier::Tier5Warrant, 5),
        (CageTier::Tier6Consensus, 5),
        (CageTier::Tier7Cbf, 6),
        (CageTier::Tier8Fiscal, 7),
    ];

    for (tier, expected_outcomes_len) in refusal_tiers {
        let receipt_deny = CageDecisionReceipt::create_and_sign(
            "spiffe://cage.local/test-agent",
            "query_balance",
            "arg-digest-deny",
            "sub-digest-deny",
            CageVerdict::Deny,
            tier,
            &format!("RULE_DENY_{:?}", tier),
            vec!["Refused".to_string()],
            Some("Refusal test".to_string()),
            1700000000000,
            &secret_key,
        );

        let resp_deny = CageEvaluationResponse {
            verdict: CageVerdict::Deny,
            rule_id: format!("RULE_DENY_{:?}", tier),
            tier,
            receipt: receipt_deny,
            governance_trace: Vec::new(),
            error_message: Some("Refusal test".to_string()),
        };

        let events = export_cage_governance_trace_v1(&dummy_req, &resp_deny);
        assert_eq!(events.len(), 1, "DENY must emit exactly 1 event");
        assert_eq!(events[0]["phase"], "DENIED");
        assert_eq!(events[0]["verdict"], "DENY");
        assert_eq!(events[0]["seal_present"], false);
        let outcomes = events[0]["outcomes"].as_array().expect("outcomes array");
        assert_eq!(
            outcomes.len(),
            expected_outcomes_len,
            "Outcomes for tier {:?} must have length {}",
            tier,
            expected_outcomes_len
        );

        trace_events.extend(events);
    }

    // Verify all emitted trace events against CAGE's formal checker scripts/check_trace_conformance.py
    let jsonl_content: String = trace_events
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";

    let python_cmd = "C:\\Python314\\python.exe";
    let script_path =
        "d:\\harfile\\cybernetic-agent-governance-engine\\scripts\\check_trace_conformance.py";
    let cage_dir = "d:\\harfile\\cybernetic-agent-governance-engine";

    if std::path::Path::new(script_path).exists() && std::path::Path::new(python_cmd).exists() {
        let mut child = std::process::Command::new(python_cmd)
            .arg(script_path)
            .current_dir(cage_dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("Failed to spawn python check_trace_conformance.py");

        use std::io::Write;
        {
            let stdin = child.stdin.as_mut().expect("Failed to open stdin");
            stdin
                .write_all(jsonl_content.as_bytes())
                .expect("Failed to write to stdin");
        }

        let output = child
            .wait_with_output()
            .expect("Failed to wait on child process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        println!("Trace check stdout:\n{}", stdout);
        if !stderr.is_empty() {
            eprintln!("Trace check stderr:\n{}", stderr);
        }

        assert_eq!(
            output.status.code(),
            Some(0),
            "check_trace_conformance.py must exit with code 0. Stderr: {}",
            stderr
        );
        assert!(
            stdout.contains("0 findings"),
            "Trace check output must confirm 0 findings, got: {}",
            stdout
        );
    } else {
        println!(
            "External check_trace_conformance.py skipped: script ({}) or python binary ({}) not found on this runner",
            script_path, python_cmd
        );
    }
}
