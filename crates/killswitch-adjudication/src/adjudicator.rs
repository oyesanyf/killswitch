//! Unified Zero-False-Positive Adjudication Gate (`ZeroFalsePositiveAdjudicator`).
//!
//! Enforces the "Never Wrong" Invariant by coordinating all 5 defense layers:
//! 1. Process Lineage Immunity & Critical System PID Whitelist (`immunity.rs`)
//! 2. Protected Local Binary BLAKE3 Hash Inventory (`inventory.rs`)
//! 3. Authenticode & Windows Catalog Verification (`win_trust.rs`)
//! 4. Autonomous REA 4-Layer Defense Engine (`rea/engine.rs`)
//! 5. Multi-Voter Consensus Engine & DLP Lineage Voter (`consensus.rs`, `voters.rs`)

use std::path::Path;
use std::sync::Arc;

use killswitch_core::killchain::is_critical_system_pid;
use killswitch_types::adjudication::{
    AdjudicationResult, BinaryTrustVerdict, ThreatCandidate, VetoReason,
};

use crate::byzantine::build_kill_switch_fraud_proof;
use crate::consensus::MultiVoterConsensusEngine;
use crate::immunity::inspect_process_lineage;
use crate::inventory::is_protected_local_binary_hash;
use crate::rea::AutonomousReaEngine;
use crate::voters::{
    AdjudicationContext, BehaviorVoter, DataLineageVoter, LiveNetworkVoter, MemoryVoter, ReaVoter,
    StaticArtifactVoter, ThreatIntelVoter,
};
use crate::win_trust::verify_binary_cryptographic_trust;

/// Unified Zero-False-Positive Adjudicator coordinating all 5 defense layers.
pub struct ZeroFalsePositiveAdjudicator {
    rea_engine: Arc<AutonomousReaEngine>,
    consensus_engine: Arc<MultiVoterConsensusEngine>,
}

impl Default for ZeroFalsePositiveAdjudicator {
    fn default() -> Self {
        Self::new()
    }
}

impl ZeroFalsePositiveAdjudicator {
    pub fn new() -> Self {
        let rea_engine = Arc::new(AutonomousReaEngine::new());
        let consensus_engine = Arc::new(MultiVoterConsensusEngine::new());

        // Register default first-class voters
        consensus_engine.register_voter(Arc::new(DataLineageVoter::new()));
        consensus_engine.register_voter(Arc::new(ReaVoter::with_engine(Arc::clone(&rea_engine))));
        consensus_engine.register_voter(Arc::new(LiveNetworkVoter::new()));
        consensus_engine.register_voter(Arc::new(BehaviorVoter::new()));
        consensus_engine.register_voter(Arc::new(MemoryVoter::new()));
        consensus_engine.register_voter(Arc::new(StaticArtifactVoter::new()));
        consensus_engine.register_voter(Arc::new(ThreatIntelVoter::new()));

        Self {
            rea_engine,
            consensus_engine,
        }
    }

    pub fn with_components(
        rea_engine: Arc<AutonomousReaEngine>,
        consensus_engine: Arc<MultiVoterConsensusEngine>,
    ) -> Self {
        Self {
            rea_engine,
            consensus_engine,
        }
    }

    pub fn rea_engine(&self) -> &Arc<AutonomousReaEngine> {
        &self.rea_engine
    }

    pub fn consensus_engine(&self) -> &Arc<MultiVoterConsensusEngine> {
        &self.consensus_engine
    }

    /// Evaluates a candidate threat through all 5 defense layers.
    pub async fn adjudicate_threat_candidate(
        &self,
        candidate: &ThreatCandidate,
        context: Option<&AdjudicationContext>,
    ) -> AdjudicationResult {
        let timestamp = chrono::Utc::now().to_rfc3339();

        // ---------------------------------------------------------------------
        // Layer 1: Critical System PID & Process Lineage Immunity (Depth <= 5)
        // ---------------------------------------------------------------------
        if let Some(pid) = candidate.pid {
            let lineage = inspect_process_lineage(pid, Some(&candidate.proc_name));
            if let Some(veto_reason) = lineage.to_veto_reason() {
                let explanation = format!(
                    "{}: target PID {} ({}) is protected under canonical system immunity",
                    veto_reason.as_str(),
                    pid,
                    candidate.proc_name
                );
                let fraud_proof = candidate.peer_id.as_deref().map(|peer| {
                    Box::new(build_kill_switch_fraud_proof(
                        peer,
                        &candidate.proc_name,
                        candidate.blake3_hash.as_deref().unwrap_or(""),
                        &explanation,
                    ))
                });
                let seal = AdjudicationResult::compute_seal("Vetoed", 0.0, &explanation, &timestamp);
                return AdjudicationResult::Vetoed {
                    reason: veto_reason,
                    explanation,
                    fraud_proof,
                    trust_verdict: None,
                    adjudication_seal: seal,
                    timestamp,
                };
            }
        } else if is_critical_system_pid(0, &candidate.proc_name) {
            let explanation = format!(
                "CRITICAL_SYSTEM_PID_VETO: process '{}' matches critical system catalog",
                candidate.proc_name
            );
            let fraud_proof = candidate.peer_id.as_deref().map(|peer| {
                Box::new(build_kill_switch_fraud_proof(
                    peer,
                    &candidate.proc_name,
                    candidate.blake3_hash.as_deref().unwrap_or(""),
                    &explanation,
                ))
            });
            let seal = AdjudicationResult::compute_seal("Vetoed", 0.0, &explanation, &timestamp);
            return AdjudicationResult::Vetoed {
                reason: VetoReason::CriticalSystemPid,
                explanation,
                fraud_proof,
                trust_verdict: None,
                adjudication_seal: seal,
                timestamp,
            };
        }

        // ---------------------------------------------------------------------
        // Layer 2: In-Memory Protected Local Binary BLAKE3 Inventory
        // ---------------------------------------------------------------------
        if let Some(ref h) = candidate.blake3_hash {
            if is_protected_local_binary_hash(h) {
                let explanation = format!(
                    "PROTECTED_LOCAL_BINARY_HASH_VETO: binary hash {} matches protected inventory",
                    h
                );
                let fraud_proof = candidate.peer_id.as_deref().map(|peer| {
                    Box::new(build_kill_switch_fraud_proof(
                        peer,
                        &candidate.proc_name,
                        h,
                        &explanation,
                    ))
                });
                let seal = AdjudicationResult::compute_seal("Vetoed", 0.0, &explanation, &timestamp);
                return AdjudicationResult::Vetoed {
                    reason: VetoReason::ProtectedBinaryHash,
                    explanation,
                    fraud_proof,
                    trust_verdict: Some(BinaryTrustVerdict::TrustedProtectedHash {
                        blake3_hash: h.clone(),
                    }),
                    adjudication_seal: seal,
                    timestamp,
                };
            }
        }

        // ---------------------------------------------------------------------
        // Layer 3: Authenticode & Windows Catalog Validation
        // ---------------------------------------------------------------------
        if let Some(ref path_str) = candidate.binary_path {
            let path = Path::new(path_str);
            if path.is_file() {
                let trust_verdict = verify_binary_cryptographic_trust(path);
                if trust_verdict.is_trusted() {
                    let (reason, explanation) = match &trust_verdict {
                        BinaryTrustVerdict::TrustedAuthenticode { signer_subject, .. } => (
                            VetoReason::AuthenticodeTrustedVendor,
                            format!(
                                "AUTHENTICODE_TRUSTED_VENDOR_VETO: binary signed by {:?}",
                                signer_subject
                            ),
                        ),
                        BinaryTrustVerdict::TrustedCatalog { .. } => (
                            VetoReason::WindowsCatalogSigned,
                            "WINDOWS_CATALOG_SIGNED_VETO: binary verified via Windows Security Catalog"
                                .to_string(),
                        ),
                        BinaryTrustVerdict::TrustedProtectedHash { blake3_hash } => (
                            VetoReason::ProtectedBinaryHash,
                            format!(
                                "PROTECTED_LOCAL_BINARY_HASH_VETO: binary hash matches {}",
                                blake3_hash
                            ),
                        ),
                        BinaryTrustVerdict::TrustedSystemPackage { .. } => (
                            VetoReason::BenignDevToolchain,
                            "TRUSTED_SYSTEM_PACKAGE_VETO: binary verified by system package manager"
                                .to_string(),
                        ),
                        _ => (
                            VetoReason::AuthenticodeTrustedVendor,
                            "TRUSTED_BINARY_VETO".to_string(),
                        ),
                    };
                    let seal = AdjudicationResult::compute_seal("Vetoed", 0.0, &explanation, &timestamp);
                    return AdjudicationResult::Vetoed {
                        reason,
                        explanation,
                        fraud_proof: None,
                        trust_verdict: Some(trust_verdict),
                        adjudication_seal: seal,
                        timestamp,
                    };
                }
            }
        }

        // ---------------------------------------------------------------------
        // Layer 4: Autonomous REA 4-Layer Defense Pre-Screening
        // ---------------------------------------------------------------------
        let target_id = candidate
            .binary_path
            .as_deref()
            .unwrap_or(&candidate.proc_name);
        let rea_eval = self.rea_engine.evaluate_detector_candidate(
            &candidate.source_detector,
            target_id,
            &candidate.detection_reason,
            candidate.initial_confidence as f64,
        );

        if rea_eval.benign_veto {
            let explanation = format!(
                "BENIGN_DEV_TOOLCHAIN_VETO: REA engine evaluated candidate as benign system/dev tool: {}",
                rea_eval.explanation
            );
            let seal = AdjudicationResult::compute_seal("Vetoed", 0.0, &explanation, &timestamp);
            return AdjudicationResult::Vetoed {
                reason: VetoReason::BenignDevToolchain,
                explanation,
                fraud_proof: None,
                trust_verdict: None,
                adjudication_seal: seal,
                timestamp,
            };
        }

        // ---------------------------------------------------------------------
        // Layer 5: Multi-Voter Consensus Engine & DLP Lineage Evaluation
        // ---------------------------------------------------------------------
        self.consensus_engine
            .adjudicate(candidate, context)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use killswitch_types::adjudication::EvidenceClass;

    #[tokio::test]
    async fn test_adjudicator_vetoes_critical_system_pid() {
        let adjudicator = ZeroFalsePositiveAdjudicator::new();
        let candidate = ThreatCandidate::new(
            Some(4),
            "system",
            "AnomalousHeuristic",
            "High CPU",
            0.99,
            EvidenceClass::Behavior,
        );

        let result = adjudicator.adjudicate_threat_candidate(&candidate, None).await;
        assert!(result.is_vetoed());
        assert_eq!(result.confidence(), 0.0);
    }

    #[tokio::test]
    async fn test_adjudicator_vetoes_protected_hash() {
        let adjudicator = ZeroFalsePositiveAdjudicator::new();
        let test_hash = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
        crate::inventory::register_protected_binary_hash(test_hash);

        let mut candidate = ThreatCandidate::new(
            Some(9999),
            "custom_runner.exe",
            "StaticDetector",
            "Suspicious import",
            0.95,
            EvidenceClass::StaticArtifact,
        );
        candidate.blake3_hash = Some(test_hash.to_string());

        let result = adjudicator.adjudicate_threat_candidate(&candidate, None).await;
        assert!(result.is_vetoed());
        assert_eq!(result.confidence(), 0.0);
    }
}
