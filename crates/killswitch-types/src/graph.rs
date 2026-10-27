use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::adjudication::{ByzantineKillSwitchFraudProof, ThreatCandidate, VoteAction};
use crate::errors::KillSwitchError;
use crate::status::{KillChainHealthProbeReport, KillChainStatus};

/// Complete 10-node lifecycle state machine for the native Rust LangGraph StateGraph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum GraphNodeId {
    #[default]
    /// 1. Passive monitoring; ETW/Sysmon, watchdog, canary tripwires.
    Monitoring,
    /// 2. Ingestion and normalization of raw telemetry signals.
    IngestingSignals,
    /// 3. Multi-vector correlation across EDR and Octopus mesh boundaries.
    CorrelatingEdrAndOctopus,
    /// 4. Zero-False-Positive Adjudication Gate ("Never Wrong" multi-voter gate).
    AdjudicatingZeroFalsePositive,
    /// 4a. Fraud proof emission node when a threat candidate is vetoed.
    VetoedWithFraudProof,
    /// 5b. Human-in-the-Loop pause gate waiting for operator confirmation token.
    AwaitingManualConfirmation,
    /// 5a/5c. Graduated native containment execution (limb autotomy, freeze, WFP/Netlink block).
    EngagingContainment,
    /// 6. Cyclic intermediate process-tree health probing (60s intervals).
    IsolatedHealthProbing,
    /// 7. Automatic early restoration (3 healthy probes) or failsafe unfreeze.
    DisarmingAndRestoring,
    /// 8. Optional local Ollama LLM forensic reasoning node.
    OptionalOllamaReasoning,
}

/// Immutable execution trace step recorded by the StateGraph engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionStep {
    pub step_index: usize,
    pub timestamp: String,
    pub node_id: GraphNodeId,
    pub input_digest: String,
    pub output_digest: String,
    pub prev_chain_hash: String,
    pub chain_hash: String,
    pub execution_duration_ms: u64,
    pub details: serde_json::Value,
}

impl ExecutionStep {
    pub const DOMAIN_TAG: &'static [u8] = b"LANGGRAPH_TRACE_STEP_V1:";

    /// Computes the cryptographic Merkle chain link:
    /// ChainLink_i = BLAKE3(ChainLink_{i-1} || step_index || timestamp || node_id || input_digest || output_digest)
    pub fn compute_chain_hash(
        prev_chain_hash: &str,
        step_index: usize,
        timestamp: &str,
        node_id: GraphNodeId,
        input_digest: &str,
        output_digest: &str,
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_TAG);
        hasher.update(prev_chain_hash.as_bytes());
        hasher.update(&step_index.to_le_bytes());
        hasher.update(timestamp.as_bytes());
        hasher.update(format!("{:?}", node_id).as_bytes());
        hasher.update(input_digest.as_bytes());
        hasher.update(output_digest.as_bytes());
        hasher.finalize().to_hex().to_string()
    }

    /// Factory method for instantiating a verified execution step.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        prev_chain_hash: &str,
        step_index: usize,
        timestamp: String,
        node_id: GraphNodeId,
        input_digest: String,
        output_digest: String,
        execution_duration_ms: u64,
        details: serde_json::Value,
    ) -> Self {
        let chain_hash = Self::compute_chain_hash(
            prev_chain_hash,
            step_index,
            &timestamp,
            node_id,
            &input_digest,
            &output_digest,
        );

        Self {
            step_index,
            timestamp,
            node_id,
            input_digest,
            output_digest,
            prev_chain_hash: prev_chain_hash.to_string(),
            chain_hash,
            execution_duration_ms,
            details,
        }
    }

    /// Verifies the cryptographic link of this step against the expected previous hash.
    pub fn verify_link(&self, expected_prev_hash: &str) -> bool {
        if self.prev_chain_hash != expected_prev_hash {
            return false;
        }
        let recomputed = Self::compute_chain_hash(
            &self.prev_chain_hash,
            self.step_index,
            &self.timestamp,
            self.node_id,
            &self.input_digest,
            &self.output_digest,
        );
        self.chain_hash == recomputed
    }
}

/// Execution mode for the LangGraph orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OrchestratorMode {
    /// Automatically engages containment upon zero-false-positive confirmation;
    /// automatically restores after 3 healthy probes or 30-min watchdog ceiling.
    #[default]
    Autonomous,
    /// Halts at `AwaitingManualConfirmation` checkpoint until authenticated operator confirms.
    Manual,
}

/// Human-in-the-Loop operator review decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorApprovalState {
    pub decision: ApprovalDecision,
    pub operator_id: String,
    pub confirmation_token: String, // e.g. "CONFIRM ISOLATE" or "CONFIRM RESTORE"
    pub timestamp: String,
    pub comments: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecision {
    Approved,
    Rejected,
    AutoApproved,
}

/// Typed, serializable state container for the LangGraph StateGraph engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchGraphState {
    /// Unique incident UUID tracking this graph execution.
    pub incident_id: String,
    /// Current active lifecycle node.
    pub current_node: GraphNodeId,
    /// Operating mode (Autonomous vs Manual).
    pub mode: OrchestratorMode,
    /// Incident creation timestamp (RFC3339).
    pub created_at: String,
    /// Last state modification timestamp (RFC3339).
    pub updated_at: String,

    /// Active threat candidates under investigation.
    pub active_threats: Vec<ThreatCandidate>,
    /// Normalized threat score from EDR and Octopus correlation (0.0 - 1.0).
    pub aggregate_threat_score: f32,
    /// Current host containment engine status.
    pub containment_status: KillChainStatus,
    /// History of intermediate health probe results.
    pub probe_results: Vec<KillChainHealthProbeReport>,
    /// Cryptographically chained execution trace history.
    pub execution_trace: Vec<ExecutionStep>,
    /// Vetoed fraud proofs emitted during adjudication.
    pub vetoed_fraud_proofs: Vec<ByzantineKillSwitchFraudProof>,
    /// HITL operator approval record, if required.
    pub operator_approval: Option<OperatorApprovalState>,
    /// Generic metadata key-value pairs.
    pub metadata: HashMap<String, String>,
}

impl KillSwitchGraphState {
    pub const GENESIS_TRACE_HASH: &'static str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    pub fn new(incident_id: impl Into<String>, mode: OrchestratorMode) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            incident_id: incident_id.into(),
            current_node: GraphNodeId::Monitoring,
            mode,
            created_at: now.clone(),
            updated_at: now,
            active_threats: Vec::new(),
            aggregate_threat_score: 0.0,
            containment_status: KillChainStatus::default(),
            probe_results: Vec::new(),
            execution_trace: Vec::new(),
            vetoed_fraud_proofs: Vec::new(),
            operator_approval: None,
            metadata: HashMap::new(),
        }
    }

    /// Appends a new execution step to the BLAKE3 hash chain.
    pub fn record_execution_step(
        &mut self,
        node_id: GraphNodeId,
        input_digest: impl Into<String>,
        output_digest: impl Into<String>,
        duration_ms: u64,
        details: serde_json::Value,
    ) {
        let prev_hash = self
            .execution_trace
            .last()
            .map(|s| s.chain_hash.as_str())
            .unwrap_or(Self::GENESIS_TRACE_HASH);

        let step_index = self.execution_trace.len();
        let timestamp = chrono::Utc::now().to_rfc3339();

        let step = ExecutionStep::new(
            prev_hash,
            step_index,
            timestamp.clone(),
            node_id,
            input_digest.into(),
            output_digest.into(),
            duration_ms,
            details,
        );

        self.execution_trace.push(step);
        self.current_node = node_id;
        self.updated_at = timestamp;
    }

    /// Verifies the full cryptographic integrity of the execution trace chain.
    pub fn verify_trace_chain(&self) -> bool {
        let mut expected_prev = Self::GENESIS_TRACE_HASH;
        for (i, step) in self.execution_trace.iter().enumerate() {
            if step.step_index != i {
                return false;
            }
            if !step.verify_link(expected_prev) {
                return false;
            }
            expected_prev = &step.chain_hash;
        }
        true
    }
}

/// Output produced by a graph node after execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNodeOutput {
    pub next_node: Option<GraphNodeId>,
    pub updated_threat_score: Option<f32>,
    pub candidate_updates: Vec<ThreatCandidate>,
    pub containment_action_taken: Option<VoteAction>,
    pub fraud_proofs_emitted: Vec<ByzantineKillSwitchFraudProof>,
    pub summary: String,
}

/// Asynchronous trait implemented by all native StateGraph nodes.
#[async_trait::async_trait]
pub trait GraphNode: Send + Sync {
    fn id(&self) -> GraphNodeId;
    async fn execute(&self, state: &KillSwitchGraphState) -> Result<GraphNodeOutput, KillSwitchError>;
}

/// Persistent checkpointer trait for saving and resuming graph states.
#[async_trait::async_trait]
pub trait StateCheckpointer: Send + Sync {
    async fn save_checkpoint(&self, state: &KillSwitchGraphState) -> Result<(), KillSwitchError>;
    async fn load_checkpoint(&self, incident_id: &str) -> Result<Option<KillSwitchGraphState>, KillSwitchError>;
    async fn list_checkpoints(&self) -> Result<Vec<String>, KillSwitchError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_step_chain_verification() {
        let mut state = KillSwitchGraphState::new("inc-001", OrchestratorMode::Autonomous);
        assert!(state.verify_trace_chain());

        state.record_execution_step(
            GraphNodeId::Monitoring,
            "hash-in-1",
            "hash-out-1",
            12,
            serde_json::json!({"action": "started"}),
        );
        state.record_execution_step(
            GraphNodeId::IngestingSignals,
            "hash-in-2",
            "hash-out-2",
            24,
            serde_json::json!({"signals_ingested": 3}),
        );
        state.record_execution_step(
            GraphNodeId::AdjudicatingZeroFalsePositive,
            "hash-in-3",
            "hash-out-3",
            48,
            serde_json::json!({"verdict": "VETOED"}),
        );

        assert_eq!(state.execution_trace.len(), 3);
        assert!(state.verify_trace_chain());

        // Tamper with output digest of step 1 -> chain must fail
        state.execution_trace[1].output_digest = "tampered-output".to_string();
        assert!(!state.verify_trace_chain());
    }
}
