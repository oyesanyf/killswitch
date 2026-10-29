//! Threat Voter Trait, Registry, and Voter Implementations.
//!
//! Includes:
//! - `ThreatVoter` async trait and `AdjudicationContext`.
//! - `VoterRegistry` for concurrent voter management.
//! - `DataLineageVoter`: Mandatory First-Class DLP Data Lineage Threat Voter.
//! - Companion voters: `ReaVoter`, `LiveNetworkVoter`, `BehaviorVoter`, `MemoryVoter`,
//!   `StaticArtifactVoter`, and `ThreatIntelVoter` (with capping <= 0.49).

use async_trait::async_trait;
use killswitch_core::killchain::is_critical_system_pid;
use killswitch_types::adjudication::{EvidenceClass, ThreatCandidate, VoteAction, VoteResult};
use killswitch_types::telemetry::SecurityEvent;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, info};

/// Classification level of DLP assets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DlpClassification {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    CrownJewel = 3,
}

/// Enforcement policy for DLP assets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DlpPolicy {
    Allow = 0,
    Audit = 1,
    Quarantine = 2,
}

/// Propagated sticky taint baggage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintBaggage {
    pub classification: DlpClassification,
    pub policy: DlpPolicy,
    pub source_sha256: String,
}

impl TaintBaggage {
    pub fn new(
        classification: DlpClassification,
        policy: DlpPolicy,
        source_sha256: impl Into<String>,
    ) -> Self {
        Self {
            classification,
            policy,
            source_sha256: source_sha256.into(),
        }
    }

    /// Merges incoming taint baggage, escalating to the highest classification and policy,
    /// and concatenating distinct SHA-256 source digests.
    pub fn merge(&mut self, incoming: &TaintBaggage) {
        self.classification = self.classification.max(incoming.classification);
        self.policy = self.policy.max(incoming.policy);

        let mut existing_hashes: Vec<String> = self
            .source_sha256
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        for incoming_hash in incoming
            .source_sha256
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
        {
            if !incoming_hash.is_empty() && !existing_hashes.contains(&incoming_hash) {
                existing_hashes.push(incoming_hash);
            }
        }

        self.source_sha256 = existing_hashes.join(",");
    }

    pub fn is_quarantine(&self) -> bool {
        self.policy == DlpPolicy::Quarantine
    }

    pub fn is_crown_jewel(&self) -> bool {
        self.classification == DlpClassification::CrownJewel
    }
}

/// Egress evaluation verdict emitted by EndpointLineageEngine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressVerdict {
    Allow,
    Block { reason: String, trace_id: String },
}

impl EgressVerdict {
    pub fn is_block(&self) -> bool {
        matches!(self, Self::Block { .. })
    }
}

/// OpenLineage Dataset Facets carrying content hash and classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenLineageDatasetFacets {
    pub content_sha256: String,
    pub dlp_classification: DlpClassification,
}

/// OpenLineage standard dataset representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenLineageDataset {
    pub namespace: String,
    pub name: String,
    pub facets: OpenLineageDatasetFacets,
}

/// Causal W3C trace link tying an event back to origin seed spans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageCausalLink {
    pub trace_id: String,
    pub span_id: String,
    pub role: String, // e.g. "INPUT"
    pub file_path: String,
}

/// Complete DLP Data Lineage context presented to the Adjudication Engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LineageAdjudicationEvidence {
    pub actor_pid: u32,
    pub actor_exe: String,
    pub parent_pid: Option<u32>,
    pub destination: String,
    pub egress_verdict: EgressVerdict,
    pub baggage: Option<TaintBaggage>,
    pub causal_links: Vec<LineageCausalLink>,
    pub input_datasets: Vec<OpenLineageDataset>,
    pub provenance_hops: Vec<String>,
}

/// Context provided to voters during candidate evaluation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AdjudicationContext {
    /// Optional DLP Lineage evidence from EndpointLineageEngine
    pub lineage_evidence: Option<LineageAdjudicationEvidence>,
    /// Optional raw security event triggering this evaluation
    pub security_event: Option<SecurityEvent>,
    /// Resolved process ancestry chain: (PID, process_name) up to depth 5
    pub process_ancestry: Vec<(u32, String)>,
    /// Host execution environment flags
    pub is_dev_environment: bool,
}

/// Abstract voter contributing evidence to the multi-voter consensus engine.
#[async_trait]
pub trait ThreatVoter: Send + Sync {
    /// Human-readable voter identifier (e.g. "DataLineageVoter", "ReaVoter").
    fn name(&self) -> &'static str;

    /// Telemetry evidence class this voter primarily represents.
    fn evidence_class(&self) -> EvidenceClass;

    /// Evaluates the candidate threat and optional context, returning a structured vote.
    async fn vote(
        &self,
        candidate: &ThreatCandidate,
        context: Option<&AdjudicationContext>,
    ) -> Option<VoteResult>;

    /// Base reliability weight of this voter (defaults to EvidenceClass::default_reliability).
    fn reliability(&self) -> f32 {
        self.evidence_class().default_reliability()
    }

    /// Indicates whether this voter executes heavy compute (disassembly, deep AI).
    fn is_heavy(&self) -> bool {
        false
    }
}

/// Thread-safe registry managing registered security voters.
#[derive(Default)]
pub struct VoterRegistry {
    voters: Vec<Arc<dyn ThreatVoter>>,
}

impl VoterRegistry {
    pub fn new() -> Self {
        Self { voters: Vec::new() }
    }

    /// Registers a new threat voter into the registry.
    pub fn register(&mut self, voter: Arc<dyn ThreatVoter>) {
        if !self.voters.iter().any(|v| v.name() == voter.name()) {
            self.voters.push(voter);
        }
    }

    /// Retrieves a voter by name.
    pub fn get_voter(&self, name: &str) -> Option<Arc<dyn ThreatVoter>> {
        self.voters.iter().find(|v| v.name() == name).cloned()
    }

    /// Retrieves all voters representing a specific evidence class.
    pub fn voters_by_class(&self, class: EvidenceClass) -> Vec<Arc<dyn ThreatVoter>> {
        self.voters
            .iter()
            .filter(|v| v.evidence_class() == class)
            .cloned()
            .collect()
    }

    /// Returns a slice of all registered voters.
    pub fn all_voters(&self) -> &[Arc<dyn ThreatVoter>] {
        &self.voters
    }

    /// Number of registered voters.
    pub fn len(&self) -> usize {
        self.voters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.voters.is_empty()
    }
}

// ============================================================================
// 1. First-Class DLP Data Lineage Threat Voter
// ============================================================================

pub struct DataLineageVoter;

impl Default for DataLineageVoter {
    fn default() -> Self {
        Self::new()
    }
}

impl DataLineageVoter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ThreatVoter for DataLineageVoter {
    fn name(&self) -> &'static str {
        "DataLineageVoter"
    }

    fn evidence_class(&self) -> EvidenceClass {
        EvidenceClass::LiveNetwork
    }

    async fn vote(
        &self,
        candidate: &ThreatCandidate,
        context: Option<&AdjudicationContext>,
    ) -> Option<VoteResult> {
        let lineage = context.and_then(|ctx| ctx.lineage_evidence.as_ref())?;
        let actor_pid = lineage.actor_pid;
        let actor_exe = &lineage.actor_exe;
        let is_critical = is_critical_system_pid(actor_pid, actor_exe);

        // Case 1: Active Egress Block on Quarantined / CrownJewel Data
        if let EgressVerdict::Block { reason: _, trace_id } = &lineage.egress_verdict {
            let baggage = lineage.baggage.as_ref();
            let source_hashes = baggage.map(|b| b.source_sha256.as_str()).unwrap_or("unknown");

            if is_critical {
                // Critical system process (e.g. powershell.exe) attempting egress of CrownJewel data:
                // Recommend network isolation / destination blocking, but annotate that the shell itself
                // must NOT be frozen/bricked, preserving OS stability.
                info!(
                    "🚨 [LINEAGE-CRITICAL-PID] Critical system process '{}' (PID {}) attempted CrownJewel egress to '{}'",
                    actor_exe, actor_pid, lineage.destination
                );
                return Some(VoteResult {
                    candidate_pid: Some(actor_pid),
                    action: VoteAction::Isolate,
                    confidence: 0.96,
                    evidence_class: EvidenceClass::LiveNetwork,
                    explanation: format!(
                        "DLP Egress Violation in Critical System Process '{}' (PID {}): trace_id={} destination={} source_hashes=[{}] datasets={} hops={:?}. Preserving PID from freeze termination; network isolation recommended.",
                        actor_exe, actor_pid, trace_id, lineage.destination, source_hashes, lineage.input_datasets.len(), lineage.provenance_hops
                    ),
                    voter_name: self.name().to_string(),
                    weight: 1.85,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            } else {
                // Non-critical process (e.g. curl.exe, 7z.exe) exfiltrating sensitive data:
                info!(
                    "🚨 [LINEAGE-EXFILTRATION] Exfiltration detected in '{}' (PID {}) to '{}': trace_id={}",
                    actor_exe, actor_pid, lineage.destination, trace_id
                );
                return Some(VoteResult {
                    candidate_pid: Some(actor_pid),
                    action: VoteAction::Isolate,
                    confidence: 0.96,
                    evidence_class: EvidenceClass::LiveNetwork,
                    explanation: format!(
                        "Verified Multi-Hop DLP Exfiltration in '{}' (PID {}): trace_id={} destination={} source_hashes=[{}] datasets={} causal_links={}",
                        actor_exe, actor_pid, trace_id, lineage.destination, source_hashes, lineage.input_datasets.len(), lineage.causal_links.len()
                    ),
                    voter_name: self.name().to_string(),
                    weight: 1.85,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        // Case 2: Multi-Hop Staging / Aggregation Behavior (File Write / Staging)
        if let Some(baggage) = &lineage.baggage {
            if baggage.is_quarantine() && lineage.input_datasets.len() >= 2 {
                return Some(VoteResult {
                    candidate_pid: Some(actor_pid),
                    action: VoteAction::Alert,
                    confidence: 0.92,
                    evidence_class: EvidenceClass::Behavior,
                    explanation: format!(
                        "DLP Multi-Source Staging in '{}' (PID {}): merged {} input datasets into quarantined staging bundle. Source hashes: [{}]",
                        actor_exe, actor_pid, lineage.input_datasets.len(), baggage.source_sha256
                    ),
                    voter_name: self.name().to_string(),
                    weight: 1.20,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        // Case 3: Legitimate Admin Process without Taint or Block
        if is_critical && lineage.egress_verdict == EgressVerdict::Allow {
            let has_quarantine_taint = lineage.baggage.as_ref().map(|b| b.is_quarantine()).unwrap_or(false);
            if !has_quarantine_taint {
                debug!(
                    "🛡️ [LINEAGE-BENIGN-VETO] Critical system process '{}' (PID {}) attested clean with zero quarantined taint",
                    actor_exe, actor_pid
                );
                return Some(VoteResult::new_veto(
                    Some(actor_pid),
                    format!("Critical system process '{}' (PID {}) attested clean by DataLineageVoter (no quarantine taint)", actor_exe, actor_pid),
                    self.name(),
                    EvidenceClass::Behavior,
                ));
            }
        }

        // Candidate fallback check: if candidate matches actor
        if candidate.proc_name == lineage.actor_exe && lineage.egress_verdict.is_block() {
            return Some(VoteResult {
                candidate_pid: candidate.pid,
                action: VoteAction::Isolate,
                confidence: 0.96,
                evidence_class: EvidenceClass::LiveNetwork,
                explanation: format!("DLP block matching candidate '{}'", candidate.proc_name),
                voter_name: self.name().to_string(),
                weight: 1.85,
                timestamp: chrono::Utc::now().to_rfc3339(),
            });
        }

        None
    }
}

// ============================================================================
// 2. REA Consensus Voter Adapter
// ============================================================================

pub struct ReaVoter {
    engine: Arc<crate::rea::AutonomousReaEngine>,
}

impl Default for ReaVoter {
    fn default() -> Self {
        Self::new()
    }
}

impl ReaVoter {
    pub fn new() -> Self {
        Self {
            engine: Arc::new(crate::rea::AutonomousReaEngine::new()),
        }
    }

    pub fn with_engine(engine: Arc<crate::rea::AutonomousReaEngine>) -> Self {
        Self { engine }
    }
}

#[async_trait]
impl ThreatVoter for ReaVoter {
    fn name(&self) -> &'static str {
        "ReaVoter"
    }

    fn evidence_class(&self) -> EvidenceClass {
        EvidenceClass::StaticArtifact
    }

    async fn vote(
        &self,
        candidate: &ThreatCandidate,
        _context: Option<&AdjudicationContext>,
    ) -> Option<VoteResult> {
        let target = candidate
            .binary_path
            .as_deref()
            .unwrap_or(&candidate.proc_name);
        let rea_vote = self.engine.cast_consensus_vote(
            target,
            &candidate.source_detector,
            &candidate.detection_reason,
            candidate.initial_confidence as f64,
        );

        if rea_vote.benign_veto {
            Some(VoteResult::new_veto(
                candidate.pid,
                rea_vote.reason,
                self.name(),
                self.evidence_class(),
            ))
        } else if rea_vote.decision == "ESCALATE_MALICIOUS" {
            Some(VoteResult {
                candidate_pid: candidate.pid,
                action: VoteAction::Isolate,
                confidence: rea_vote.confidence as f32,
                evidence_class: self.evidence_class(),
                explanation: rea_vote.reason,
                voter_name: self.name().to_string(),
                weight: rea_vote.weight as f32,
                timestamp: rea_vote.timestamp,
            })
        } else {
            Some(VoteResult {
                candidate_pid: candidate.pid,
                action: VoteAction::Alert,
                confidence: rea_vote.confidence as f32,
                evidence_class: self.evidence_class(),
                explanation: rea_vote.reason,
                voter_name: self.name().to_string(),
                weight: rea_vote.weight as f32,
                timestamp: rea_vote.timestamp,
            })
        }
    }
}

// ============================================================================
// 3. Live Network Voter
// ============================================================================

pub struct LiveNetworkVoter;

impl Default for LiveNetworkVoter {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveNetworkVoter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ThreatVoter for LiveNetworkVoter {
    fn name(&self) -> &'static str {
        "LiveNetworkVoter"
    }

    fn evidence_class(&self) -> EvidenceClass {
        EvidenceClass::LiveNetwork
    }

    async fn vote(
        &self,
        candidate: &ThreatCandidate,
        _context: Option<&AdjudicationContext>,
    ) -> Option<VoteResult> {
        if candidate.evidence_class == EvidenceClass::LiveNetwork
            || candidate.detection_reason.to_ascii_lowercase().contains("c2")
            || candidate.detection_reason.to_ascii_lowercase().contains("beacon")
            || candidate.detection_reason.to_ascii_lowercase().contains("network")
        {
            Some(VoteResult {
                candidate_pid: candidate.pid,
                action: if candidate.initial_confidence >= 0.80 {
                    VoteAction::Isolate
                } else {
                    VoteAction::Alert
                },
                confidence: candidate.initial_confidence,
                evidence_class: EvidenceClass::LiveNetwork,
                explanation: format!("[LiveNetwork] {}", candidate.detection_reason),
                voter_name: self.name().to_string(),
                weight: 1.0,
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
        } else {
            None
        }
    }
}

// ============================================================================
// 4. Behavioral Voter
// ============================================================================

pub struct BehaviorVoter;

impl Default for BehaviorVoter {
    fn default() -> Self {
        Self::new()
    }
}

impl BehaviorVoter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ThreatVoter for BehaviorVoter {
    fn name(&self) -> &'static str {
        "BehaviorVoter"
    }

    fn evidence_class(&self) -> EvidenceClass {
        EvidenceClass::Behavior
    }

    async fn vote(
        &self,
        candidate: &ThreatCandidate,
        _context: Option<&AdjudicationContext>,
    ) -> Option<VoteResult> {
        let reason_low = candidate.detection_reason.to_ascii_lowercase();
        let cmd_low = candidate
            .command_line
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();

        if candidate.evidence_class == EvidenceClass::Behavior
            || crate::rea::has_active_lotl_or_exploit_indicators(&reason_low)
            || crate::rea::has_active_lotl_or_exploit_indicators(&cmd_low)
        {
            let conf = if crate::rea::has_active_lotl_or_exploit_indicators(&cmd_low)
                || crate::rea::has_active_lotl_or_exploit_indicators(&reason_low)
            {
                (candidate.initial_confidence + 0.20).clamp(0.90, 1.0)
            } else {
                candidate.initial_confidence
            };

            Some(VoteResult {
                candidate_pid: candidate.pid,
                action: if conf >= 0.85 {
                    VoteAction::Isolate
                } else {
                    VoteAction::Alert
                },
                confidence: conf,
                evidence_class: EvidenceClass::Behavior,
                explanation: format!(
                    "[Behavior] Confirmed behavioral telemetry: {}",
                    candidate.detection_reason
                ),
                voter_name: self.name().to_string(),
                weight: 1.0,
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
        } else {
            None
        }
    }
}

// ============================================================================
// 5. Memory Voter
// ============================================================================

pub struct MemoryVoter;

impl Default for MemoryVoter {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryVoter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ThreatVoter for MemoryVoter {
    fn name(&self) -> &'static str {
        "MemoryVoter"
    }

    fn evidence_class(&self) -> EvidenceClass {
        EvidenceClass::Memory
    }

    async fn vote(
        &self,
        candidate: &ThreatCandidate,
        _context: Option<&AdjudicationContext>,
    ) -> Option<VoteResult> {
        let reason_low = candidate.detection_reason.to_ascii_lowercase();
        if candidate.evidence_class == EvidenceClass::Memory
            || reason_low.contains("lsass")
            || reason_low.contains("minidump")
            || reason_low.contains("injection")
            || reason_low.contains("virtualallocex")
            || reason_low.contains("writeprocessmemory")
        {
            Some(VoteResult {
                candidate_pid: candidate.pid,
                action: VoteAction::Isolate,
                confidence: candidate.initial_confidence.max(0.92),
                evidence_class: EvidenceClass::Memory,
                explanation: format!("[Memory] Code injection or memory anomaly: {}", candidate.detection_reason),
                voter_name: self.name().to_string(),
                weight: 1.0,
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
        } else {
            None
        }
    }
}

// ============================================================================
// 6. Static Artifact Voter
// ============================================================================

pub struct StaticArtifactVoter;

impl Default for StaticArtifactVoter {
    fn default() -> Self {
        Self::new()
    }
}

impl StaticArtifactVoter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ThreatVoter for StaticArtifactVoter {
    fn name(&self) -> &'static str {
        "StaticArtifactVoter"
    }

    fn evidence_class(&self) -> EvidenceClass {
        EvidenceClass::StaticArtifact
    }

    async fn vote(
        &self,
        candidate: &ThreatCandidate,
        _context: Option<&AdjudicationContext>,
    ) -> Option<VoteResult> {
        if candidate.evidence_class == EvidenceClass::StaticArtifact
            || candidate.yara_rule.is_some()
            || candidate.detection_reason.to_ascii_lowercase().contains("yara")
        {
            Some(VoteResult {
                candidate_pid: candidate.pid,
                action: VoteAction::Alert,
                confidence: candidate.initial_confidence,
                evidence_class: EvidenceClass::StaticArtifact,
                explanation: format!("[StaticArtifact] Rule or signature match: {}", candidate.detection_reason),
                voter_name: self.name().to_string(),
                weight: 1.0,
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
        } else {
            None
        }
    }
}

// ============================================================================
// 7. Threat Intel Voter (Strictly Capped <= 0.49)
// ============================================================================

pub struct ThreatIntelVoter;

impl Default for ThreatIntelVoter {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatIntelVoter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ThreatVoter for ThreatIntelVoter {
    fn name(&self) -> &'static str {
        "ThreatIntelVoter"
    }

    fn evidence_class(&self) -> EvidenceClass {
        EvidenceClass::ThreatIntel
    }

    async fn vote(
        &self,
        candidate: &ThreatCandidate,
        _context: Option<&AdjudicationContext>,
    ) -> Option<VoteResult> {
        if candidate.evidence_class == EvidenceClass::ThreatIntel
            || candidate.detection_reason.to_ascii_lowercase().contains("cve")
            || candidate.detection_reason.to_ascii_lowercase().contains("ioc")
            || candidate.detection_reason.to_ascii_lowercase().contains("threat intel")
        {
            Some(VoteResult {
                candidate_pid: candidate.pid,
                action: VoteAction::Monitor,
                confidence: candidate.initial_confidence.min(0.49),
                evidence_class: EvidenceClass::ThreatIntel,
                explanation: format!("[ThreatIntel] External feed correlation (capped at <= 0.49): {}", candidate.detection_reason),
                voter_name: self.name().to_string(),
                weight: 0.8,
                timestamp: chrono::Utc::now().to_rfc3339(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_datalineage_voter_exfiltration_vote() {
        let voter = DataLineageVoter::new();
        let candidate = ThreatCandidate::new(
            Some(5001),
            "curl.exe",
            "LineageWatcher",
            "Outbound upload",
            0.90,
            EvidenceClass::LiveNetwork,
        );

        let baggage = TaintBaggage::new(
            DlpClassification::CrownJewel,
            DlpPolicy::Quarantine,
            "aaa111,bbb222",
        );

        let evidence = LineageAdjudicationEvidence {
            actor_pid: 5001,
            actor_exe: "curl.exe".to_string(),
            parent_pid: Some(4812),
            destination: "https://external-drop.example.com/upload".to_string(),
            egress_verdict: EgressVerdict::Block {
                reason: "QUARANTINE active".to_string(),
                trace_id: "w3c-trace-999".to_string(),
            },
            baggage: Some(baggage),
            causal_links: vec![],
            input_datasets: vec![],
            provenance_hops: vec![],
        };

        let ctx = AdjudicationContext {
            lineage_evidence: Some(evidence),
            ..Default::default()
        };

        let vote = voter.vote(&candidate, Some(&ctx)).await;
        assert!(vote.is_some());
        let v = vote.unwrap();
        assert_eq!(v.action, VoteAction::Isolate);
        assert_eq!(v.confidence, 0.96);
        assert!(v.explanation.contains("w3c-trace-999"));
        assert!(v.explanation.contains("aaa111,bbb222"));
    }

    #[tokio::test]
    async fn test_datalineage_voter_clean_admin_powershell_veto() {
        let voter = DataLineageVoter::new();
        let candidate = ThreatCandidate::new(
            Some(2104),
            "powershell.exe",
            "CLIWatcher",
            "Get-Process command",
            0.10,
            EvidenceClass::Behavior,
        );

        let evidence = LineageAdjudicationEvidence {
            actor_pid: 2104,
            actor_exe: "powershell.exe".to_string(),
            parent_pid: Some(1000),
            destination: "local".to_string(),
            egress_verdict: EgressVerdict::Allow,
            baggage: None,
            causal_links: vec![],
            input_datasets: vec![],
            provenance_hops: vec![],
        };

        let ctx = AdjudicationContext {
            lineage_evidence: Some(evidence),
            ..Default::default()
        };

        let vote = voter.vote(&candidate, Some(&ctx)).await;
        assert!(vote.is_some());
        let v = vote.unwrap();
        assert!(v.is_veto());
        assert!(v.weight < 0.0);
    }

    #[test]
    fn test_taint_baggage_merge() {
        let mut b1 = TaintBaggage::new(
            DlpClassification::Internal,
            DlpPolicy::Audit,
            "hash1",
        );
        let b2 = TaintBaggage::new(
            DlpClassification::CrownJewel,
            DlpPolicy::Quarantine,
            "hash2",
        );
        b1.merge(&b2);
        assert_eq!(b1.classification, DlpClassification::CrownJewel);
        assert_eq!(b1.policy, DlpPolicy::Quarantine);
        assert!(b1.source_sha256.contains("hash1"));
        assert!(b1.source_sha256.contains("hash2"));
    }
}
