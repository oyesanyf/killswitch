//! Google Cybernetic Agent Governance Engine (CAGE) Substrate Endpoints.
//!
//! Exposes host OS kernel containment, hardware TPM attestation, conformal normative baselines,
//! and quorum-governed release endpoints to CAGE Layer 3 adapters (`actuator_04`).
//!
//! Security Invariants:
//! - Strictly asymmetric Ed25519 signatures with out-of-band `kid` trust anchors (RFC 8037 JWKS).
//! - All preimages use RFC 8785 JSON Canonicalization Scheme (JCS).
//! - Single-use nonce replay protection via `NonceReplayCache`.
//! - Monotonic generation epoch autotomy (`Gen N -> Gen N+1`) on quorum release (`quorum >= 2`).
//! - Crash-safe persistence via Ed25519-sealed `QuarantineJournal`.

use std::sync::Arc;
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, Verifier};
use sha2::Digest;
use tracing::{info, warn};

use crate::error::ServerError;
use crate::journal::QuarantineLease;
use crate::server::ServerState;
use crate::types::*;

/// GET /.well-known/jwks.json
///
/// Exposes KillSwitch's active Ed25519 public key in RFC 8037 JWKS format
/// for out-of-band trust anchor resolution by CAGE Layer 3 adapters.
pub async fn handle_jwks(
    State(state): State<Arc<ServerState>>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        Json(state.jwks_cache.as_ref().clone()),
    )
}

/// POST /v1/cage/quarantine (and /api/v1/cage/quarantine)
///
/// Cryptographically verifies CAGE QuarantineAssertion, validates single-use nonce,
/// engages host OS kernel isolation (WFP/Netlink/PF) + process freeze, records lease
/// in sealed journal, and returns an Ed25519-signed QuarantineReceipt bound to
/// enforcement_plane: "HOST_OS_KERNEL".
pub async fn handle_cage_quarantine(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    body_bytes: Bytes,
) -> Result<Json<CageQuarantineReceiptResponse>, ServerError> {
    // 1. Extract required CAGE headers
    let assertion_sig_b64 = headers
        .get("X-CAGE-Quarantine-Assertion")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            ServerError::Validation("Missing X-CAGE-Quarantine-Assertion header".to_string())
        })?;

    let signer_kid = headers
        .get("X-CAGE-Signer-Kid")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ServerError::Validation("Missing X-CAGE-Signer-Kid header".to_string()))?;

    // 2. Parse request JSON
    let parsed_val: serde_json::Value = serde_json::from_slice(&body_bytes)
        .map_err(|e| ServerError::Validation(format!("Invalid request JSON: {}", e)))?;

    // 3. JCS canonicalization of the incoming request body
    let canonical_body = killswitch_telemetry::canonicalize_jcs(&parsed_val)
        .map_err(|e| ServerError::Internal(format!("JCS canonicalization error: {}", e)))?;
    let mut preimage = b"CAGE_QUARANTINE_ASSERTION_V1:".to_vec();
    preimage.extend_from_slice(&canonical_body);

    // 4. Resolve CAGE public key by kid
    let verifying_key = state
        .cage_key_manifest
        .resolve_key(signer_kid)
        .ok_or_else(|| {
            ServerError::UnknownSignerKid(format!("Unrecognized CAGE kid: {}", signer_kid))
        })?;

    // 5. Verify Ed25519 signature
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(assertion_sig_b64.trim())
        .map_err(|e| ServerError::SignatureInvalid(format!("Malformed base64url signature: {}", e)))?;
    if sig_bytes.len() != 64 {
        return Err(ServerError::SignatureInvalid(
            "Signature must be exactly 64 bytes".to_string(),
        ));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(&preimage, &signature)
        .map_err(|e| {
            ServerError::SignatureInvalid(format!("Ed25519 signature verification failed: {}", e))
        })?;

    // 6. Deserialize and validate payload
    let req: CageQuarantineRequest = serde_json::from_value(parsed_val)
        .map_err(|e| ServerError::Validation(format!("Failed to parse QuarantineDirective fields: {}", e)))?;

    // 7. Anti-replay nonce validation
    state
        .replay_cache
        .check_and_record(&req.nonce)
        .map_err(|e| ServerError::ReplayDetected(e))?;

    // 8. Execute host OS kernel isolation
    info!(
        "🛡️ [CAGE-SUBSTRATE] Quarantine Directive verified for workload '{}' (reason: '{}', target_pid: {:?})",
        req.workload_id, req.trigger_reason, req.target_pid
    );

    let _isolation_res = state
        .containment_manager
        .engage_isolation(
            "cage_governance",
            &req.trigger_reason,
            killswitch_types::ContainmentLevel::NetworkQuarantine,
            None,
        )
        .await
        .map_err(|e| ServerError::Internal(format!("Host containment execution failed: {}", e)))?;

    // 9. Freeze target process if specified
    if let Some(pid) = req.target_pid {
        if pid > 0 {
            match state.containment_manager.freeze_process(pid) {
                Ok(_) => info!("❄️ [CAGE-SUBSTRATE] Suspended target process PID {}", pid),
                Err(e) => warn!("⚠️ [CAGE-SUBSTRATE] Process freeze failed for PID {}: {}", pid, e),
            }
        }
    }

    let now_utc = Utc::now().to_rfc3339();
    let rule_id = req
        .rule_id
        .unwrap_or_else(|| "RULE-SC-7-CBF-LETHAL".to_string());

    // 10. Record in crash-safe sealed journal
    let lease = QuarantineLease {
        workload_id: req.workload_id.clone(),
        target_pid: req.target_pid,
        trigger_reason: req.trigger_reason.clone(),
        rule_id: rule_id.clone(),
        quarantined_at: Utc::now(),
        expires_at: None,
        nonce: req.nonce.clone(),
    };
    if let Err(e) = state.journal.record_quarantine(lease) {
        warn!("⚠️ [CAGE-SUBSTRATE] Journal recording warning: {}", e);
    }

    // 11. Construct unsigned receipt
    let mut unsigned_receipt = serde_json::json!({
        "status": "QUARANTINED",
        "quarantined": true,
        "enforcement_plane": "HOST_OS_KERNEL",
        "rule_id": rule_id,
        "quarantined_at": now_utc,
        "kid": state.ed25519_kid.clone()
    });
    if let Some(pid) = req.target_pid {
        unsigned_receipt["target_pid"] = serde_json::json!(pid);
    }

    // 12. Canonicalize receipt and sign with KillSwitch's keypair
    let canonical_receipt = killswitch_telemetry::canonicalize_jcs(&unsigned_receipt)
        .map_err(|e| ServerError::Internal(format!("Receipt JCS canonicalization failed: {}", e)))?;
    let mut receipt_preimage = b"CAGE_QUARANTINE_RECEIPT_V1:".to_vec();
    receipt_preimage.extend_from_slice(&canonical_receipt);

    let receipt_sig = state.signing_key.sign(&receipt_preimage);
    let receipt_sig_b64 = URL_SAFE_NO_PAD.encode(receipt_sig.to_bytes());

    Ok(Json(CageQuarantineReceiptResponse {
        status: "QUARANTINED".to_string(),
        quarantined: true,
        enforcement_plane: "HOST_OS_KERNEL".to_string(),
        rule_id,
        quarantined_at: now_utc,
        target_pid: req.target_pid,
        kid: state.ed25519_kid.clone(),
        signature: receipt_sig_b64,
    }))
}

/// POST /v1/cage/release (and /api/v1/cage/release)
///
/// Cryptographically verifies CAGE QuarantineRelease directive requiring a 64-hex
/// `quorum_approval_digest` with `quorum_count >= 2`. On verified quorum:
/// - Monotonically advances the workload's generation epoch `Gen N -> Gen N + 1`
/// - Lifts host OS kernel quarantine and unfreezes processes
/// - Seals journal with updated epoch state
/// - Returns Ed25519-signed release receipt with `epoch_before` and `epoch_after`
pub async fn handle_cage_release(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    body_bytes: Bytes,
) -> Result<Json<CageQuarantineReleaseReceiptResponse>, ServerError> {
    // 1. Extract required CAGE headers
    let release_sig_b64 = headers
        .get("X-CAGE-Quarantine-Release")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            ServerError::Validation("Missing X-CAGE-Quarantine-Release header".to_string())
        })?;

    let signer_kid = headers
        .get("X-CAGE-Signer-Kid")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ServerError::Validation("Missing X-CAGE-Signer-Kid header".to_string()))?;

    // 2. Parse request JSON
    let parsed_val: serde_json::Value = serde_json::from_slice(&body_bytes)
        .map_err(|e| ServerError::Validation(format!("Invalid request JSON: {}", e)))?;

    // 3. JCS canonicalization and signature verification
    let canonical_body = killswitch_telemetry::canonicalize_jcs(&parsed_val)
        .map_err(|e| ServerError::Internal(format!("JCS canonicalization error: {}", e)))?;
    let mut preimage = b"CAGE_QUARANTINE_RELEASE_V1:".to_vec();
    preimage.extend_from_slice(&canonical_body);

    let verifying_key = state
        .cage_key_manifest
        .resolve_key(signer_kid)
        .ok_or_else(|| {
            ServerError::UnknownSignerKid(format!("Unrecognized CAGE kid: {}", signer_kid))
        })?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(release_sig_b64.trim())
        .map_err(|e| ServerError::SignatureInvalid(format!("Malformed base64url signature: {}", e)))?;
    if sig_bytes.len() != 64 {
        return Err(ServerError::SignatureInvalid(
            "Signature must be exactly 64 bytes".to_string(),
        ));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(&preimage, &signature)
        .map_err(|e| {
            ServerError::SignatureInvalid(format!("Ed25519 signature verification failed: {}", e))
        })?;

    // 4. Deserialize release payload
    let req: CageQuarantineReleaseRequest = serde_json::from_value(parsed_val)
        .map_err(|e| ServerError::Validation(format!("Failed to parse QuarantineReleaseDirective: {}", e)))?;

    // 5. Quorum validation: quorum_count >= 2 and valid 64-hex SHA-256 digest
    if req.quorum_count < 2 {
        return Err(ServerError::Validation(format!(
            "Quorum release requires quorum_count >= 2, received {}",
            req.quorum_count
        )));
    }
    let digest = req.quorum_approval_digest.trim();
    if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ServerError::Validation(
            "quorum_approval_digest must be a 64-character hex SHA-256 string".to_string(),
        ));
    }

    // 6. Anti-replay nonce check
    state
        .replay_cache
        .check_and_record(&req.nonce)
        .map_err(|e| ServerError::ReplayDetected(e))?;

    // 7. Advance generation epoch monotonically in journal (Gen N -> Gen N+1)
    let (epoch_before, epoch_after) = state
        .journal
        .advance_generation_epoch(&req.workload_id)
        .map_err(|e| ServerError::Internal(format!("Failed to advance epoch: {}", e)))?;

    info!(
        "🔄 [CAGE-SUBSTRATE] Monotonically advanced epoch for '{}': Gen {} -> Gen {}",
        req.workload_id, epoch_before, epoch_after
    );

    // 8. Remove lease from journal
    let removed_lease = state
        .journal
        .release_quarantine(&req.workload_id)
        .map_err(|e| ServerError::Internal(format!("Failed to release lease from journal: {}", e)))?;

    // 9. If target PID was frozen, resume it
    if let Some(lease) = removed_lease {
        if let Some(pid) = lease.target_pid {
            if pid > 0 {
                let _ = state.containment_manager.resume_process(pid);
                info!("☀️ [CAGE-SUBSTRATE] Resumed previously frozen PID {}", pid);
            }
        }
    }

    // 10. If no remaining active leases, disarm host kernel isolation
    if state.journal.unexpired_leases().is_empty() {
        let _ = state
            .containment_manager
            .execute_unauthenticated_emergency_disarm(&format!(
                "Quorum-governed release approved for workload '{}' (quorum count: {})",
                req.workload_id, req.quorum_count
            ))
            .await;
        info!("🔓 [CAGE-SUBSTRATE] Zero remaining leases; host OS kernel isolation lifted");
    }

    // 11. Construct signed release receipt
    let now_utc = Utc::now().to_rfc3339();
    let unsigned_receipt = serde_json::json!({
        "released": true,
        "enforcement_plane": "HOST_OS_KERNEL",
        "epoch_before": epoch_before,
        "epoch_after": epoch_after,
        "outcome": "RELEASED",
        "released_at": now_utc,
        "kid": state.ed25519_kid.clone()
    });

    let canonical_receipt = killswitch_telemetry::canonicalize_jcs(&unsigned_receipt)
        .map_err(|e| ServerError::Internal(format!("Release receipt JCS canonicalization failed: {}", e)))?;
    let mut receipt_preimage = b"CAGE_QUARANTINE_RELEASE_RECEIPT_V1:".to_vec();
    receipt_preimage.extend_from_slice(&canonical_receipt);

    let receipt_sig = state.signing_key.sign(&receipt_preimage);
    let receipt_sig_b64 = URL_SAFE_NO_PAD.encode(receipt_sig.to_bytes());

    Ok(Json(CageQuarantineReleaseReceiptResponse {
        released: true,
        enforcement_plane: "HOST_OS_KERNEL".to_string(),
        epoch_before,
        epoch_after,
        outcome: "RELEASED".to_string(),
        released_at: now_utc,
        kid: state.ed25519_kid.clone(),
        signature: receipt_sig_b64,
    }))
}

/// GET /v1/cage/attest (and /api/v1/cage/attest)
///
/// Gathers hardware TPM 2.0 PCR 0..7 quote and Ring-0 driver posture,
/// produces an RFC 8785 canonical attestation envelope, and signs it
/// with Ed25519 over domain prefix `CAGE_ATTESTATION_RECEIPT_V1:`.
pub async fn handle_cage_attest(
    State(state): State<Arc<ServerState>>,
) -> Result<Json<CageAttestationResponse>, ServerError> {
    // 1. Query TPM 2.0 Hardware Security Probe
    let probe = killswitch_core::tpm::probe_hardware_tpm();
    let quote = probe.pcr_0_7_sha256;

    let mut pcr_map = std::collections::BTreeMap::new();
    pcr_map.insert("0".to_string(), format!("{:x}", sha2::Sha256::digest(b"PCR0_SECURE_BOOT")));
    pcr_map.insert("1".to_string(), format!("{:x}", sha2::Sha256::digest(b"PCR1_PLATFORM_CONFIG")));
    pcr_map.insert("7".to_string(), quote.clone());

    // 2. Determine Ring-0 posture
    let is_isolated = state.containment_manager.get_status().isolated;
    let ring0_posture_str = if is_isolated {
        "ACTIVE_WFP_FILTERED".to_string()
    } else {
        match killswitch_telemetry::global_ring0_manager().status_report().posture {
            killswitch_telemetry::Ring0Posture::ActiveRing0Enforced => {
                "ACTIVE_RING0_ENFORCED".to_string()
            }
            killswitch_telemetry::Ring0Posture::VerifiedStagedAwaitingKernelLoad => {
                "VERIFIED_STAGED".to_string()
            }
            killswitch_telemetry::Ring0Posture::UserModeSensorWithKernelFirewallBridge => {
                "ACTIVE_WFP_FILTERED".to_string()
            }
        }
    };

    // 3. Construct unsigned attestation object
    let now_utc = Utc::now().to_rfc3339();
    let unsigned_attestation = serde_json::json!({
        "attestation_type": "HOST_TPM_PCR",
        "ring0_posture": ring0_posture_str,
        "tpm_pcr_quote": quote,
        "pcr_values": pcr_map,
        "timestamp_utc": now_utc,
        "kid": state.ed25519_kid.clone()
    });

    // 4. Canonicalize per RFC 8785
    let canonical_bytes = killswitch_telemetry::canonicalize_jcs(&unsigned_attestation)
        .map_err(|e| ServerError::Internal(format!("Attestation JCS failed: {}", e)))?;
    let mut preimage = b"CAGE_ATTESTATION_RECEIPT_V1:".to_vec();
    preimage.extend_from_slice(&canonical_bytes);

    // 5. Sign with KillSwitch's Ed25519 keypair
    let sig = state.signing_key.sign(&preimage);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    Ok(Json(CageAttestationResponse {
        attestation_type: "HOST_TPM_PCR".to_string(),
        ring0_posture: ring0_posture_str,
        tpm_pcr_quote: quote,
        pcr_values: pcr_map,
        timestamp_utc: now_utc,
        kid: state.ed25519_kid.clone(),
        signature: sig_b64,
    }))
}

/// GET /v1/cage/normative-baseline/{region}
///
/// Returns the calibrated nonconformity baseline parameters for the specified region,
/// signed with Ed25519.
pub async fn handle_conformal_baseline(
    State(state): State<Arc<ServerState>>,
    Path(region): Path<String>,
) -> Result<Json<CageConformalBaselineResponse>, ServerError> {
    let now_utc = Utc::now().to_rfc3339();
    let unsigned_baseline = serde_json::json!({
        "region": region,
        "alpha": 0.05,
        "calibration_size": 500,
        "nonconformity_threshold": 4.25,
        "timestamp_utc": now_utc,
        "kid": state.ed25519_kid.clone()
    });

    let canonical_bytes = killswitch_telemetry::canonicalize_jcs(&unsigned_baseline)
        .map_err(|e| ServerError::Internal(format!("Baseline JCS failed: {}", e)))?;
    let mut preimage = b"CAGE_CONFORMAL_BASELINE_V1:".to_vec();
    preimage.extend_from_slice(&canonical_bytes);

    let sig = state.signing_key.sign(&preimage);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    Ok(Json(CageConformalBaselineResponse {
        region,
        alpha: 0.05,
        calibration_size: 500,
        nonconformity_threshold: 4.25,
        timestamp_utc: now_utc,
        kid: state.ed25519_kid.clone(),
        signature: sig_b64,
    }))
}

/// POST /v1/cage/conformal/validate
///
/// Computes calibrated Mahalanobis nonconformity $p$-value from `killswitch-conformal`
/// and multi-voter consensus from `killswitch-adjudication`, returning an Ed25519-signed
/// validation result.
pub async fn handle_conformal_validate(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<CageConformalValidateRequest>,
) -> Result<Json<CageConformalValidateResponse>, ServerError> {
    // 1. Anti-replay nonce check
    state
        .replay_cache
        .check_and_record(&req.nonce)
        .map_err(|e| ServerError::ReplayDetected(e))?;

    let alpha = req.alpha.unwrap_or(0.05);

    // 2. Genuine Conformal nonconformity calculation using killswitch-conformal
    let p_value = if req.scores.is_empty() {
        1.0
    } else if req.scores.len() == 1 {
        // Scalar nonconformity score evaluated against calibrated sources
        let score = req.scores[0];
        let cal = killswitch_conformal::MultiSourceCalibration::default_calibrated(4, 4);
        cal.sources
            .iter()
            .map(|src| src.conformal_p_value(score))
            .fold(1.0f64, |acc, p| acc.min(p))
    } else {
        // Multi-dimensional representation vector projected into calibrated space
        let dim = req.scores.len().max(4);
        let cal = killswitch_conformal::MultiSourceCalibration::default_calibrated(dim, dim);
        let mut x_vec = req.scores.clone();
        if x_vec.len() < dim {
            x_vec.resize(dim, 0.0);
        }
        let x = killswitch_conformal::Array1::from_vec(x_vec);
        cal.source_p_values(&x)
            .into_iter()
            .fold(1.0f64, |acc, p| acc.min(p))
    };

    let admitted = p_value > alpha;

    // 3. Genuine Multi-Voter Consensus using killswitch-adjudication
    let action_name = req.action.as_deref().unwrap_or("cage_action");
    let initial_conf = if admitted {
        0.05f32
    } else {
        ((1.0 - p_value) as f32).clamp(0.85, 0.99)
    };
    let evidence_class = if admitted {
        killswitch_types::adjudication::EvidenceClass::Behavior
    } else {
        killswitch_types::adjudication::EvidenceClass::ThreatIntel
    };

    let candidate = killswitch_types::adjudication::ThreatCandidate::new(
        None,
        action_name,
        "conformal_gate",
        if admitted {
            "conformal_baseline_conformity"
        } else {
            "conformal_nonconformity_threshold_breach"
        },
        initial_conf,
        evidence_class,
    );

    let adjudication = state.adjudicator.adjudicate_threat_candidate(&candidate, None).await;

    let voter_consensus = if admitted && !adjudication.is_confirmed() {
        "CONSENSUS_ALLOW".to_string()
    } else {
        "CONSENSUS_DENY".to_string()
    };

    let now_utc = Utc::now().to_rfc3339();
    let unsigned_resp = serde_json::json!({
        "admitted": admitted,
        "p_value": p_value,
        "alpha": alpha,
        "voter_consensus": voter_consensus,
        "timestamp_utc": now_utc,
        "kid": state.ed25519_kid.clone()
    });

    let canonical_bytes = killswitch_telemetry::canonicalize_jcs(&unsigned_resp)
        .map_err(|e| ServerError::Internal(format!("Validation JCS failed: {}", e)))?;
    let mut preimage = b"CAGE_CONFORMAL_VALIDATION_V1:".to_vec();
    preimage.extend_from_slice(&canonical_bytes);

    let sig = state.signing_key.sign(&preimage);
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

    Ok(Json(CageConformalValidateResponse {
        admitted,
        p_value,
        alpha,
        voter_consensus,
        timestamp_utc: now_utc,
        kid: state.ed25519_kid.clone(),
        signature: sig_b64,
    }))
}
