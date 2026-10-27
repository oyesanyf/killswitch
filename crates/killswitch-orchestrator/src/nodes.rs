//! # 10 Concrete Lifecycle Node Implementations
//!
//! Provides the concrete node behaviors for each discrete stage of the StateGraph.

use std::sync::Arc;
use async_trait::async_trait;
use chrono::Utc;
use tracing::info;

use killswitch_adjudication::ZeroFalsePositiveAdjudicator;
use killswitch_core::killchain::HostContainmentManager;
use killswitch_telemetry::correlator::EventCorrelator;
use killswitch_telemetry::otel_lineage::EndpointLineageEngine;
use killswitch_types::adjudication::{AdjudicationResult, ByzantineKillSwitchFraudProof, VoteAction};
use killswitch_types::errors::{KillSwitchError, Result};
use killswitch_types::graph::{GraphNodeId, GraphNodeOutput, KillSwitchGraphState, OrchestratorMode, StateCheckpointer};
use killswitch_types::status::{ContainmentLevel, HealthProbeRunner};

use crate::graph::LifecycleNode;
use crate::lineage_trigger::LineageTriggerEvaluator;
use crate::ollama::OllamaReasoningEngine;
use crate::state::LifecycleStage;

// =============================================================================
// 1. IngestNode
// =============================================================================
#[derive(Debug, Default)]
pub struct IngestNode;

#[async_trait]
impl LifecycleNode for IngestNode {
    fn stage(&self) -> LifecycleStage {
        LifecycleStage::Ingest
    }

    async fn execute(&self, state: &mut KillSwitchGraphState) -> Result<GraphNodeOutput> {
        state.updated_at = Utc::now().to_rfc3339();
        Ok(GraphNodeOutput {
            next_node: Some(GraphNodeId::CorrelatingEdrAndOctopus),
            updated_threat_score: None,
            candidate_updates: vec![],
            containment_action_taken: None,
            fraud_proofs_emitted: vec![],
            summary: format!(
                "Ingested telemetry signals; active candidates: {}",
                state.active_threats.len()
            ),
        })
    }
}

// =============================================================================
// 2. CorrelateNode
// =============================================================================
pub struct CorrelateNode {
    pub correlator: Option<Arc<EventCorrelator>>,
}

impl CorrelateNode {
    pub fn new(correlator: Option<Arc<EventCorrelator>>) -> Self {
        Self { correlator }
    }
}

#[async_trait]
impl LifecycleNode for CorrelateNode {
    fn stage(&self) -> LifecycleStage {
        LifecycleStage::Correlate
    }

    async fn execute(&self, state: &mut KillSwitchGraphState) -> Result<GraphNodeOutput> {
        if let Some(corr) = &self.correlator {
            for candidate in &state.active_threats {
                if let Some(pid) = candidate.pid {
                    if let Some(score) = corr.get_process_score(pid) {
                        if score > state.aggregate_threat_score {
                            state.aggregate_threat_score = score;
                        }
                    }
                }
            }
        } else if !state.active_threats.is_empty() && state.aggregate_threat_score < 0.85 {
            state.aggregate_threat_score = 0.85;
        }

        let score = state.aggregate_threat_score;

        Ok(GraphNodeOutput {
            next_node: Some(GraphNodeId::AdjudicatingZeroFalsePositive),
            updated_threat_score: Some(score),
            candidate_updates: vec![],
            containment_action_taken: None,
            fraud_proofs_emitted: vec![],
            summary: format!("Correlated signals; aggregate threat score: {:.2}", score),
        })
    }
}

// =============================================================================
// 3. AdjudicateNode
// =============================================================================
pub struct AdjudicateNode {
    pub adjudicator: Arc<ZeroFalsePositiveAdjudicator>,
}

impl AdjudicateNode {
    pub fn new(adjudicator: Arc<ZeroFalsePositiveAdjudicator>) -> Self {
        Self { adjudicator }
    }
}

#[async_trait]
impl LifecycleNode for AdjudicateNode {
    fn stage(&self) -> LifecycleStage {
        LifecycleStage::Adjudicate
    }

    async fn execute(&self, state: &mut KillSwitchGraphState) -> Result<GraphNodeOutput> {
        let mut fraud_proofs = Vec::new();
        let mut confirmed_count = 0;

        for candidate in &state.active_threats {
            let verdict = self.adjudicator.adjudicate_threat_candidate(candidate, None).await;
            match verdict {
                AdjudicationResult::ConfirmedThreat { confidence, .. } => {
                    confirmed_count += 1;
                    if confidence > state.aggregate_threat_score {
                        state.aggregate_threat_score = confidence;
                    }
                }
                AdjudicationResult::Vetoed { reason, explanation, fraud_proof, .. } => {
                    let proof = if let Some(p) = fraud_proof {
                        *p
                    } else {
                        ByzantineKillSwitchFraudProof::new(
                            "adjudicator",
                            candidate.peer_id.as_deref().unwrap_or("local"),
                            candidate.blake3_hash.as_deref().unwrap_or("unknown"),
                            candidate.proc_name.clone(),
                            format!("Vetoed by adjudicator: {:?} ({})", reason, explanation),
                        )
                    };
                    state.vetoed_fraud_proofs.push(proof.clone());
                    fraud_proofs.push(proof);
                }
                _ => {}
            }
        }

        Ok(GraphNodeOutput {
            next_node: Some(GraphNodeId::AdjudicatingZeroFalsePositive),
            updated_threat_score: Some(state.aggregate_threat_score),
            candidate_updates: vec![],
            containment_action_taken: if confirmed_count > 0 {
                Some(VoteAction::Isolate)
            } else {
                None
            },
            fraud_proofs_emitted: fraud_proofs,
            summary: format!(
                "Adjudication complete: {} confirmed, {} vetoed with fraud proof",
                confirmed_count,
                state.vetoed_fraud_proofs.len()
            ),
        })
    }
}

// =============================================================================
// 4. LineageTriggerNode
// =============================================================================
pub struct LineageTriggerNode {
    pub evaluator: LineageTriggerEvaluator,
}

impl LineageTriggerNode {
    pub fn new(
        lineage_engine: Arc<EndpointLineageEngine>,
        adjudicator: Arc<ZeroFalsePositiveAdjudicator>,
    ) -> Self {
        Self {
            evaluator: LineageTriggerEvaluator::new(lineage_engine, adjudicator),
        }
    }
}

#[async_trait]
impl LifecycleNode for LineageTriggerNode {
    fn stage(&self) -> LifecycleStage {
        LifecycleStage::LineageTrigger
    }

    async fn execute(&self, state: &mut KillSwitchGraphState) -> Result<GraphNodeOutput> {
        if let Some(candidate) = self.evaluator.evaluate_dlp_trigger(state).await? {
            state.active_threats.push(candidate.clone());
            state.aggregate_threat_score = 0.96;
            Ok(GraphNodeOutput {
                next_node: Some(GraphNodeId::OptionalOllamaReasoning),
                updated_threat_score: Some(0.96),
                candidate_updates: vec![candidate],
                containment_action_taken: Some(VoteAction::Isolate),
                fraud_proofs_emitted: vec![],
                summary: "Autonomous DLP Lineage trigger confirmed exfiltration violation"
                    .to_string(),
            })
        } else {
            Ok(GraphNodeOutput {
                next_node: Some(GraphNodeId::OptionalOllamaReasoning),
                updated_threat_score: None,
                candidate_updates: vec![],
                containment_action_taken: None,
                fraud_proofs_emitted: vec![],
                summary: "No DLP Lineage violations detected".to_string(),
            })
        }
    }
}

// =============================================================================
// 5. ReasonOllamaNode
// =============================================================================
pub struct ReasonOllamaNode {
    pub ollama: Arc<OllamaReasoningEngine>,
}

impl ReasonOllamaNode {
    pub fn new(ollama: Arc<OllamaReasoningEngine>) -> Self {
        Self { ollama }
    }
}

#[async_trait]
impl LifecycleNode for ReasonOllamaNode {
    fn stage(&self) -> LifecycleStage {
        LifecycleStage::ReasonOllama
    }

    async fn execute(&self, state: &mut KillSwitchGraphState) -> Result<GraphNodeOutput> {
        let prompt = format!(
            "Analyze incident {} with threat score {:.2} and {} active threats",
            state.incident_id,
            state.aggregate_threat_score,
            state.active_threats.len()
        );

        let reasoning = self.ollama.evaluate_forensics(&prompt).await;

        state
            .metadata
            .insert("ollama_model".to_string(), reasoning.model_used.clone());
        state
            .metadata
            .insert("ollama_verdict".to_string(), reasoning.forensic_verdict);
        state.metadata.insert(
            "ollama_offline_fallback".to_string(),
            reasoning.is_offline_fallback.to_string(),
        );

        Ok(GraphNodeOutput {
            next_node: Some(GraphNodeId::AwaitingManualConfirmation),
            updated_threat_score: None,
            candidate_updates: vec![],
            containment_action_taken: None,
            fraud_proofs_emitted: vec![],
            summary: format!(
                "Ollama reasoning complete (model: {}, fallback: {})",
                reasoning.model_used, reasoning.is_offline_fallback
            ),
        })
    }
}

// =============================================================================
// 6. DecideNode
// =============================================================================
#[derive(Debug, Default)]
pub struct DecideNode;

#[async_trait]
impl LifecycleNode for DecideNode {
    fn stage(&self) -> LifecycleStage {
        LifecycleStage::Decide
    }

    async fn execute(&self, state: &mut KillSwitchGraphState) -> Result<GraphNodeOutput> {
        match state.mode {
            OrchestratorMode::Manual => {
                if let Some(approval) = &state.operator_approval {
                    Ok(GraphNodeOutput {
                        next_node: Some(GraphNodeId::EngagingContainment),
                        updated_threat_score: None,
                        candidate_updates: vec![],
                        containment_action_taken: Some(VoteAction::Isolate),
                        fraud_proofs_emitted: vec![],
                        summary: format!(
                            "Manual operator approval received: {:?}",
                            approval.decision
                        ),
                    })
                } else {
                    Ok(GraphNodeOutput {
                        next_node: Some(GraphNodeId::AwaitingManualConfirmation),
                        updated_threat_score: None,
                        candidate_updates: vec![],
                        containment_action_taken: None,
                        fraud_proofs_emitted: vec![],
                        summary: "Paused awaiting manual operator confirmation token".to_string(),
                    })
                }
            }
            OrchestratorMode::Autonomous => {
                let should_isolate = state.aggregate_threat_score >= 0.85
                    || !state.active_threats.is_empty();

                let action = if should_isolate {
                    Some(VoteAction::Isolate)
                } else {
                    None
                };

                Ok(GraphNodeOutput {
                    next_node: Some(GraphNodeId::EngagingContainment),
                    updated_threat_score: None,
                    candidate_updates: vec![],
                    containment_action_taken: action,
                    fraud_proofs_emitted: vec![],
                    summary: format!(
                        "Autonomous decision evaluated: should_isolate = {}",
                        should_isolate
                    ),
                })
            }
        }
    }
}

// =============================================================================
// 7. ContainNode
// =============================================================================
pub struct ContainNode {
    pub host_manager: Arc<HostContainmentManager>,
}

impl ContainNode {
    pub fn new(host_manager: Arc<HostContainmentManager>) -> Self {
        Self { host_manager }
    }
}

#[async_trait]
impl LifecycleNode for ContainNode {
    fn stage(&self) -> LifecycleStage {
        LifecycleStage::Contain
    }

    async fn execute(&self, state: &mut KillSwitchGraphState) -> Result<GraphNodeOutput> {
        let should_isolate = state.aggregate_threat_score >= 0.85
            || !state.active_threats.is_empty()
            || (state.mode == OrchestratorMode::Manual && state.operator_approval.is_some());

        if should_isolate && !state.containment_status.isolated {
            info!("🚨 [CONTAIN-NODE] Engaging host containment via HostContainmentManager");
            let new_status = self
                .host_manager
                .engage_isolation(
                    "killswitch-orchestrator",
                    "LangGraph verified zero-false-positive threat candidate",
                    ContainmentLevel::HermeticIsolation,
                    None,
                )
                .await?;

            state.containment_status = new_status;

            Ok(GraphNodeOutput {
                next_node: Some(GraphNodeId::IsolatedHealthProbing),
                updated_threat_score: None,
                candidate_updates: vec![],
                containment_action_taken: Some(VoteAction::Isolate),
                fraud_proofs_emitted: vec![],
                summary: "Host containment engaged successfully".to_string(),
            })
        } else {
            Ok(GraphNodeOutput {
                next_node: Some(GraphNodeId::Monitoring),
                updated_threat_score: None,
                candidate_updates: vec![],
                containment_action_taken: None,
                fraud_proofs_emitted: vec![],
                summary: "Containment not required or already isolated".to_string(),
            })
        }
    }
}

// =============================================================================
// 8. MonitorNode
// =============================================================================
pub struct MonitorNode {
    pub host_manager: Arc<HostContainmentManager>,
}

impl MonitorNode {
    pub fn new(host_manager: Arc<HostContainmentManager>) -> Self {
        Self { host_manager }
    }
}

#[async_trait]
impl LifecycleNode for MonitorNode {
    fn stage(&self) -> LifecycleStage {
        LifecycleStage::Monitor
    }

    async fn execute(&self, state: &mut KillSwitchGraphState) -> Result<GraphNodeOutput> {
        let probe_report = self.host_manager.run_probe()?;
        state.probe_results.push(probe_report.clone());

        let eligible = probe_report.eligible_for_early_rollback;

        Ok(GraphNodeOutput {
            next_node: if eligible {
                Some(GraphNodeId::DisarmingAndRestoring)
            } else {
                Some(GraphNodeId::IsolatedHealthProbing)
            },
            updated_threat_score: None,
            candidate_updates: vec![],
            containment_action_taken: None,
            fraud_proofs_emitted: vec![],
            summary: format!(
                "Health probe executed: {} consecutive clean probes (eligible for rollback: {})",
                probe_report.consecutive_healthy_probes, eligible
            ),
        })
    }
}

// =============================================================================
// 9. RollbackNode
// =============================================================================
pub struct RollbackNode {
    pub host_manager: Arc<HostContainmentManager>,
}

impl RollbackNode {
    pub fn new(host_manager: Arc<HostContainmentManager>) -> Self {
        Self { host_manager }
    }
}

#[async_trait]
impl LifecycleNode for RollbackNode {
    fn stage(&self) -> LifecycleStage {
        LifecycleStage::Rollback
    }

    async fn execute(&self, state: &mut KillSwitchGraphState) -> Result<GraphNodeOutput> {
        info!("🟢 [ROLLBACK-NODE] Disarming host containment via emergency rollback");
        let restored_status = self
            .host_manager
            .execute_unauthenticated_emergency_disarm(
                "Health probe confirmed clean endpoint across 3 consecutive cycles",
            )
            .await?;

        state.containment_status = restored_status;

        Ok(GraphNodeOutput {
            next_node: Some(GraphNodeId::Monitoring),
            updated_threat_score: Some(0.0),
            candidate_updates: vec![],
            containment_action_taken: Some(VoteAction::Monitor),
            fraud_proofs_emitted: vec![],
            summary: "Host containment cleanly disarmed; system restored".to_string(),
        })
    }
}

// =============================================================================
// 10. TerminalNode
// =============================================================================
pub struct TerminalNode {
    pub checkpointer: Option<Arc<dyn StateCheckpointer>>,
}

impl TerminalNode {
    pub fn new(checkpointer: Option<Arc<dyn StateCheckpointer>>) -> Self {
        Self { checkpointer }
    }
}

#[async_trait]
impl LifecycleNode for TerminalNode {
    fn stage(&self) -> LifecycleStage {
        LifecycleStage::Terminal
    }

    async fn execute(&self, state: &mut KillSwitchGraphState) -> Result<GraphNodeOutput> {
        let trace_valid = state.verify_trace_chain();
        if !trace_valid {
            return Err(KillSwitchError::CryptoError(
                "TerminalNode detected cryptographic BLAKE3 trace chain corruption".to_string(),
            ));
        }

        if let Some(cp) = &self.checkpointer {
            cp.save_checkpoint(state).await?;
        }

        Ok(GraphNodeOutput {
            next_node: Some(GraphNodeId::Monitoring),
            updated_threat_score: None,
            candidate_updates: vec![],
            containment_action_taken: None,
            fraud_proofs_emitted: vec![],
            summary: format!(
                "Lifecycle completed cleanly (trace steps: {}, trace valid: true)",
                state.execution_trace.len()
            ),
        })
    }
}
