//! # LangGraph State and Lifecycle Definitions
//!
//! Provides the 10 discrete lifecycle stages and state transition structures.

use killswitch_types::graph::GraphNodeId;
use serde::{Deserialize, Serialize};

/// The 10 discrete lifecycle transitions of the KillSwitch LangGraph StateGraph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LifecycleStage {
    /// 1. Passive ingestion of raw telemetry and EDR signals.
    Ingest,
    /// 2. Causal graph, attack graph, and PhaseLock drift correlation.
    Correlate,
    /// 3. Zero-False-Positive REA adjudication gate.
    Adjudicate,
    /// 4. DLP OpenLineage / OpenTelemetry provenance trigger node.
    LineageTrigger,
    /// 5. Optional local Ollama reasoning node (Dynamic Memory Law & 400ms timeout).
    ReasonOllama,
    /// 6. Decision gate (Autonomous mode vs Manual HITL pause).
    Decide,
    /// 7. Graduated native containment execution (WFP/Netlink network isolation & process freeze).
    Contain,
    /// 8. Cyclic process-tree health probe monitor (60s intervals).
    Monitor,
    /// 9. Reversible disarm and clean process resumption.
    Rollback,
    /// 10. Final lifecycle state, checkpointer commit, and BLAKE3 verification.
    Terminal,
}

impl Default for LifecycleStage {
    fn default() -> Self {
        Self::Ingest
    }
}

impl LifecycleStage {
    /// Maps 10-node LifecycleStage to killswitch-types GraphNodeId.
    pub fn to_graph_node_id(&self) -> GraphNodeId {
        match self {
            Self::Ingest => GraphNodeId::IngestingSignals,
            Self::Correlate => GraphNodeId::CorrelatingEdrAndOctopus,
            Self::Adjudicate => GraphNodeId::AdjudicatingZeroFalsePositive,
            Self::LineageTrigger => GraphNodeId::AdjudicatingZeroFalsePositive,
            Self::ReasonOllama => GraphNodeId::OptionalOllamaReasoning,
            Self::Decide => GraphNodeId::AwaitingManualConfirmation,
            Self::Contain => GraphNodeId::EngagingContainment,
            Self::Monitor => GraphNodeId::IsolatedHealthProbing,
            Self::Rollback => GraphNodeId::DisarmingAndRestoring,
            Self::Terminal => GraphNodeId::Monitoring,
        }
    }

    /// Maps killswitch-types GraphNodeId back to LifecycleStage.
    pub fn from_graph_node_id(node_id: GraphNodeId) -> Self {
        match node_id {
            GraphNodeId::Monitoring => Self::Terminal,
            GraphNodeId::IngestingSignals => Self::Ingest,
            GraphNodeId::CorrelatingEdrAndOctopus => Self::Correlate,
            GraphNodeId::AdjudicatingZeroFalsePositive => Self::Adjudicate,
            GraphNodeId::VetoedWithFraudProof => Self::Terminal,
            GraphNodeId::AwaitingManualConfirmation => Self::Decide,
            GraphNodeId::EngagingContainment => Self::Contain,
            GraphNodeId::IsolatedHealthProbing => Self::Monitor,
            GraphNodeId::DisarmingAndRestoring => Self::Rollback,
            GraphNodeId::OptionalOllamaReasoning => Self::ReasonOllama,
        }
    }
}

/// Execution step transition result emitted after a StateGraph step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepTransition {
    pub from_stage: LifecycleStage,
    pub to_stage: LifecycleStage,
    pub duration_ms: u64,
    pub threat_score: f32,
    pub is_isolated: bool,
    pub is_paused: bool,
    pub is_terminal: bool,
    pub summary: String,
}
