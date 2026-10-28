//! # Decoupled LangGraph Orchestrator Bridge
//!
//! Provides an asynchronous trait abstraction over the LangGraph execution engine,
//! allowing the HTTP server to step the graph, inspect state, and update modes.

use async_trait::async_trait;
use tokio::sync::RwLock;
use std::sync::Arc;

use killswitch_types::adjudication::ThreatCandidate;
use killswitch_types::graph::{
    GraphNodeId, GraphNodeOutput, KillSwitchGraphState, OrchestratorMode,
};

use crate::error::ServerError;

#[async_trait]
pub trait OrchestratorBridge: Send + Sync {
    async fn get_state(&self) -> KillSwitchGraphState;
    async fn set_mode(&self, mode: OrchestratorMode) -> Result<(), ServerError>;
    async fn step(&self, input: Option<serde_json::Value>, force_node: Option<GraphNodeId>) -> Result<GraphNodeOutput, ServerError>;
    async fn submit_threat(&self, candidate: ThreatCandidate) -> Result<GraphNodeOutput, ServerError>;
}

/// In-memory bridge implementation executing transitions and maintaining BLAKE3 trace chains.
pub struct InMemoryOrchestratorBridge {
    state: Arc<RwLock<KillSwitchGraphState>>,
}

impl Default for InMemoryOrchestratorBridge {
    fn default() -> Self {
        Self::new(OrchestratorMode::Autonomous)
    }
}

impl InMemoryOrchestratorBridge {
    pub fn new(mode: OrchestratorMode) -> Self {
        let incident_id = format!("inc-{}", uuid::Uuid::new_v4());
        Self {
            state: Arc::new(RwLock::new(KillSwitchGraphState::new(incident_id, mode))),
        }
    }

    pub fn with_state(state: Arc<RwLock<KillSwitchGraphState>>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl OrchestratorBridge for InMemoryOrchestratorBridge {
    async fn get_state(&self) -> KillSwitchGraphState {
        self.state.read().await.clone()
    }

    async fn set_mode(&self, mode: OrchestratorMode) -> Result<(), ServerError> {
        let mut state = self.state.write().await;
        state.mode = mode;
        Ok(())
    }

    async fn step(
        &self,
        input: Option<serde_json::Value>,
        force_node: Option<GraphNodeId>,
    ) -> Result<GraphNodeOutput, ServerError> {
        let mut state = self.state.write().await;

        let current = state.current_node;
        let next = force_node.unwrap_or(match current {
            GraphNodeId::Monitoring => GraphNodeId::IngestingSignals,
            GraphNodeId::IngestingSignals => GraphNodeId::CorrelatingEdrAndOctopus,
            GraphNodeId::CorrelatingEdrAndOctopus => GraphNodeId::AdjudicatingZeroFalsePositive,
            GraphNodeId::AdjudicatingZeroFalsePositive => GraphNodeId::OptionalOllamaReasoning,
            GraphNodeId::OptionalOllamaReasoning => GraphNodeId::EngagingContainment,
            GraphNodeId::EngagingContainment => GraphNodeId::IsolatedHealthProbing,
            GraphNodeId::IsolatedHealthProbing => GraphNodeId::DisarmingAndRestoring,
            GraphNodeId::DisarmingAndRestoring => GraphNodeId::Monitoring,
            _ => GraphNodeId::Monitoring,
        });

        let summary = format!("Step transition from {:?} to {:?}", current, next);
        let input_digest = blake3::hash(input.as_ref().map(|v| v.to_string()).unwrap_or_default().as_bytes()).to_hex().to_string();
        let output_digest = blake3::hash(summary.as_bytes()).to_hex().to_string();

        state.record_execution_step(
            next,
            input_digest,
            output_digest,
            10,
            serde_json::json!({"summary": summary.clone()}),
        );

        Ok(GraphNodeOutput {
            next_node: Some(next),
            updated_threat_score: Some(state.aggregate_threat_score),
            candidate_updates: vec![],
            containment_action_taken: None,
            fraud_proofs_emitted: vec![],
            summary,
        })
    }

    async fn submit_threat(&self, candidate: ThreatCandidate) -> Result<GraphNodeOutput, ServerError> {
        let mut state = self.state.write().await;
        state.active_threats.push(candidate);
        if state.aggregate_threat_score < 0.85 {
            state.aggregate_threat_score = 0.85;
        }

        let summary = format!("Threat submitted; active candidates: {}", state.active_threats.len());
        Ok(GraphNodeOutput {
            next_node: Some(GraphNodeId::AdjudicatingZeroFalsePositive),
            updated_threat_score: Some(state.aggregate_threat_score),
            candidate_updates: state.active_threats.clone(),
            containment_action_taken: None,
            fraud_proofs_emitted: vec![],
            summary,
        })
    }
}
