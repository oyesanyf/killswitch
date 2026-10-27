//! Multi-Voter Consensus Engine for Zero-False-Positive Adjudication.
//!
//! Orchestrates votes across 6 orthogonal telemetry evidence classes + DLP Data Lineage:
//! - Applies discrete corroboration multiplier:
//!   - 0 classes -> 0.00
//!   - 1 class   -> 0.52 (Strict Single-Voter Penalty, preventing unilateral killswitch triggers)
//!   - 2 classes -> 0.82 (Awaiting Manual Confirmation ceiling)
//!   - >=3 classes -> 1.00 (Autonomous Containment >= 0.94)
//! - Enforces Strict Veto Propagation: any voter with negative weight (< 0.0) or
//!   `is_veto() == true` collapses consensus to 0.0 and emits `AdjudicationResult::Vetoed`.
//! - Enforces domain suppression rules: pure ThreatIntel <= 0.49, pure StaticArtifact <= 0.68.

use killswitch_types::adjudication::{
    calculate_consensus, AdjudicationResult, EvidenceClass, ThreatCandidate, VetoReason,
    VoteAction, VoteResult,
};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info};

use crate::voters::{AdjudicationContext, ThreatVoter, VoterRegistry};

/// Core Multi-Voter Consensus Engine.
pub struct MultiVoterConsensusEngine {
    registry: Arc<RwLock<VoterRegistry>>,
    isolation_threshold: f32, // Default: 0.94
    manual_threshold: f32,    // Default: 0.82
}

impl Default for MultiVoterConsensusEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiVoterConsensusEngine {
    pub const DEFAULT_ISOLATION_THRESHOLD: f32 = 0.94;
    pub const DEFAULT_MANUAL_THRESHOLD: f32 = 0.82;

    pub fn new() -> Self {
        Self {
            registry: Arc::new(RwLock::new(VoterRegistry::new())),
            isolation_threshold: Self::DEFAULT_ISOLATION_THRESHOLD,
            manual_threshold: Self::DEFAULT_MANUAL_THRESHOLD,
        }
    }

    pub fn with_thresholds(isolation_threshold: f32, manual_threshold: f32) -> Self {
        Self {
            registry: Arc::new(RwLock::new(VoterRegistry::new())),
            isolation_threshold,
            manual_threshold,
        }
    }

    /// Registers a new threat voter into the engine's registry.
    pub fn register_voter(&self, voter: Arc<dyn ThreatVoter>) {
        self.registry.write().register(voter);
    }

    /// Collects votes asynchronously from all registered voters.
    pub async fn collect_votes(
        &self,
        candidate: &ThreatCandidate,
        context: Option<&AdjudicationContext>,
    ) -> Vec<VoteResult> {
        let voters = self.registry.read().all_voters().to_vec();
        let mut futures = Vec::with_capacity(voters.len());

        for voter in voters {
            let cand = candidate.clone();
            let ctx = context.cloned();
            futures.push(tokio::spawn(async move {
                voter.vote(&cand, ctx.as_ref()).await
            }));
        }

        let mut votes = Vec::new();
        for handle in futures {
            if let Ok(Some(vote)) = handle.await {
                votes.push(vote);
            }
        }

        votes
    }

    /// Orchestrates collected evidence and evaluates consensus invariants.
    pub fn orchestrate_evidence(
        &self,
        votes: &[VoteResult],
        candidate: &ThreatCandidate,
    ) -> AdjudicationResult {
        let now = chrono::Utc::now().to_rfc3339();

        if votes.is_empty() {
            return AdjudicationResult::MonitorOnly {
                confidence: 0.0,
                explanation: "No security voter returned an actionable verdict".to_string(),
                timestamp: now,
            };
        }

        // 1. Strict Veto Propagation Check: any vote with weight < 0.0 forces immediate veto
        if let Some(veto_vote) = votes.iter().find(|v| v.is_veto()) {
            info!(
                "🛑 [CONSENSUS-VETO] Voter '{}' issued strict veto on '{}': {}",
                veto_vote.voter_name, candidate.proc_name, veto_vote.explanation
            );
            let seal = AdjudicationResult::compute_seal("Vetoed", 0.0, &veto_vote.explanation, &now);
            return AdjudicationResult::Vetoed {
                reason: VetoReason::CriticalSystemPid,
                explanation: format!(
                    "Strict consensus veto cast by {}: {}",
                    veto_vote.voter_name, veto_vote.explanation
                ),
                fraud_proof: None,
                trust_verdict: None,
                adjudication_seal: seal,
                timestamp: now,
            };
        }

        // 2. Compute Multi-Class Consensus via calculate_consensus
        let (raw_consensus, distinct_classes) = calculate_consensus(votes);

        // 3. Evaluate Class Composition & Domain Suppression Rules
        let mut classes = HashSet::new();
        let mut has_live_network = false;
        let mut has_behavior = false;
        let mut has_memory = false;
        let mut has_static = false;
        let mut threat_intel_only = true;

        for v in votes {
            classes.insert(v.evidence_class);
            match v.evidence_class {
                EvidenceClass::LiveNetwork => {
                    has_live_network = true;
                    threat_intel_only = false;
                }
                EvidenceClass::Behavior => {
                    has_behavior = true;
                    threat_intel_only = false;
                }
                EvidenceClass::Memory => {
                    has_memory = true;
                    threat_intel_only = false;
                }
                EvidenceClass::StaticArtifact => {
                    has_static = true;
                    threat_intel_only = false;
                }
                EvidenceClass::ThreatIntel => {}
                EvidenceClass::Reputation => {
                    threat_intel_only = false;
                }
            }
        }

        let mut final_confidence = raw_consensus;

        // Rule: ThreatIntel-only evidence cannot exceed 0.49
        if threat_intel_only {
            final_confidence = final_confidence.min(0.49);
        }

        // Rule: StaticArtifact-only uncorroborated evidence cannot exceed 0.68
        if has_static && !has_live_network && !has_behavior && !has_memory && distinct_classes < 3 {
            final_confidence = final_confidence.min(0.68);
        }

        let explanation = format!(
            "Consensus: classes=[{}] distinct={} final_confidence={:.4} raw={:.4}",
            classes
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join("+"),
            distinct_classes,
            final_confidence,
            raw_consensus
        );

        // 4. Threshold & Verdict Mapping
        // Confirmed Threat requires confidence >= 0.94 AND >= 3 independent evidence classes
        if final_confidence >= self.isolation_threshold && distinct_classes >= 3 {
            let seal = AdjudicationResult::compute_seal(
                "ConfirmedThreat",
                final_confidence,
                &explanation,
                &now,
            );
            info!(
                "🚨 [CONSENSUS-CONFIRMED] Threat confirmed against '{}': {}",
                candidate.proc_name, explanation
            );
            AdjudicationResult::ConfirmedThreat {
                recommended_action: VoteAction::Isolate,
                confidence: final_confidence,
                independent_classes: distinct_classes,
                votes: votes.to_vec(),
                explanation,
                adjudication_seal: seal,
                timestamp: now,
            }
        } else if final_confidence >= self.manual_threshold {
            // Awaiting Manual Confirmation (HITL): confidence >= 0.82
            let seal = AdjudicationResult::compute_seal(
                "AwaitingManualConfirmation",
                final_confidence,
                &explanation,
                &now,
            );
            info!(
                "⚠️ [CONSENSUS-HITL] Awaiting manual confirmation for '{}': {}",
                candidate.proc_name, explanation
            );
            AdjudicationResult::AwaitingManualConfirmation {
                confidence: final_confidence,
                votes: votes.to_vec(),
                explanation,
                adjudication_seal: seal,
                timestamp: now,
            }
        } else {
            // Monitor Only: confidence < 0.82
            debug!(
                "👁️ [CONSENSUS-MONITOR] Candidate '{}' tracked as monitor-only: {}",
                candidate.proc_name, explanation
            );
            AdjudicationResult::MonitorOnly {
                confidence: final_confidence,
                explanation,
                timestamp: now,
            }
        }
    }

    /// End-to-end adjudication pipeline combining vote collection and orchestration.
    pub async fn adjudicate(
        &self,
        candidate: &ThreatCandidate,
        context: Option<&AdjudicationContext>,
    ) -> AdjudicationResult {
        let votes = self.collect_votes(candidate, context).await;
        self.orchestrate_evidence(&votes, candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_voter_penalty_capped_below_isolation() {
        let engine = MultiVoterConsensusEngine::new();
        let candidate = ThreatCandidate::new(
            Some(4412),
            "unknown.exe",
            "NetworkDetector",
            "Outbound beaconing",
            1.0,
            EvidenceClass::LiveNetwork,
        );

        let votes = vec![VoteResult::new(
            Some(4412),
            VoteAction::Isolate,
            1.0,
            EvidenceClass::LiveNetwork,
            "Beacon detected",
            "LiveNetworkVoter",
        )];

        let result = engine.orchestrate_evidence(&votes, &candidate);
        // Multiplier 0.52 on 1.0 -> 0.52 < 0.82 -> MonitorOnly
        assert!(!result.is_confirmed());
        assert!(!result.is_awaiting_confirmation());
        assert!(result.confidence() <= 0.55);
    }

    #[test]
    fn test_two_classes_reaches_hitl_threshold() {
        let engine = MultiVoterConsensusEngine::new();
        let candidate = ThreatCandidate::new(
            Some(4412),
            "unknown.exe",
            "Correlator",
            "Multiple signals",
            1.0,
            EvidenceClass::Behavior,
        );

        let votes = vec![
            VoteResult::new(
                Some(4412),
                VoteAction::Isolate,
                1.0,
                EvidenceClass::LiveNetwork,
                "Beacon detected",
                "LiveNetworkVoter",
            ),
            VoteResult::new(
                Some(4412),
                VoteAction::Isolate,
                1.0,
                EvidenceClass::Behavior,
                "Process injection",
                "BehaviorVoter",
            ),
        ];

        let result = engine.orchestrate_evidence(&votes, &candidate);
        // Multiplier 0.82 on 1.0 -> 0.82 -> AwaitingManualConfirmation
        assert!(result.is_awaiting_confirmation());
        assert!(!result.is_confirmed());
    }

    #[test]
    fn test_three_classes_confirms_autonomous_isolation() {
        let engine = MultiVoterConsensusEngine::new();
        let candidate = ThreatCandidate::new(
            Some(4412),
            "malware.exe",
            "Correlator",
            "Confirmed multi-stage threat",
            0.98,
            EvidenceClass::Behavior,
        );

        let votes = vec![
            VoteResult::new(
                Some(4412),
                VoteAction::Isolate,
                0.98,
                EvidenceClass::LiveNetwork,
                "C2 active",
                "LiveNetworkVoter",
            ),
            VoteResult::new(
                Some(4412),
                VoteAction::Isolate,
                0.96,
                EvidenceClass::Behavior,
                "Privilege escalation",
                "BehaviorVoter",
            ),
            VoteResult::new(
                Some(4412),
                VoteAction::Isolate,
                0.95,
                EvidenceClass::Memory,
                "LSASS dump",
                "MemoryVoter",
            ),
        ];

        let result = engine.orchestrate_evidence(&votes, &candidate);
        assert!(result.is_confirmed());
        assert!(result.confidence() >= 0.94);
    }

    #[test]
    fn test_strict_veto_propagation() {
        let engine = MultiVoterConsensusEngine::new();
        let candidate = ThreatCandidate::new(
            Some(4),
            "system",
            "Detector",
            "Alert on system",
            1.0,
            EvidenceClass::Behavior,
        );

        let votes = vec![
            VoteResult::new(
                Some(4),
                VoteAction::Isolate,
                1.0,
                EvidenceClass::LiveNetwork,
                "C2 active",
                "LiveNetworkVoter",
            ),
            VoteResult::new_veto(
                Some(4),
                "System kernel PID is immune",
                "ImmunityVoter",
                EvidenceClass::Behavior,
            ),
        ];

        let result = engine.orchestrate_evidence(&votes, &candidate);
        assert!(result.is_vetoed());
        assert_eq!(result.confidence(), 0.0);
    }

    #[test]
    fn test_threat_intel_only_capped_at_049() {
        let engine = MultiVoterConsensusEngine::new();
        let candidate = ThreatCandidate::new(
            Some(1234),
            "sample.exe",
            "CVEWatcher",
            "CVE match",
            1.0,
            EvidenceClass::ThreatIntel,
        );

        let votes = vec![
            VoteResult::new(
                Some(1234),
                VoteAction::Alert,
                1.0,
                EvidenceClass::ThreatIntel,
                "IoC match",
                "ThreatIntelVoter1",
            ),
            VoteResult::new(
                Some(1234),
                VoteAction::Alert,
                1.0,
                EvidenceClass::ThreatIntel,
                "CVE match",
                "ThreatIntelVoter2",
            ),
        ];

        let result = engine.orchestrate_evidence(&votes, &candidate);
        assert!(!result.is_confirmed());
        assert!(result.confidence() <= 0.49);
    }
}
