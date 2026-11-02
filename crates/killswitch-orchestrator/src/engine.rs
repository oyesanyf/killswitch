//! # High-Level Orchestrator Service Coordinator
//!
//! Encapsulates the StateGraph, durable checkpointer, and active incident state.

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use killswitch_adjudication::ZeroFalsePositiveAdjudicator;
use killswitch_core::killchain::HostContainmentManager;
use killswitch_telemetry::{
    global_cage_kernel, CageDecisionReceipt, CageEvaluationRequest, CageVerdict,
    CageWarrantToken, HitlConsensusApproval,
};
use killswitch_telemetry::otel_lineage::EndpointLineageEngine;
use killswitch_types::adjudication::ThreatCandidate;
use killswitch_types::errors::{KillSwitchError, Result};
use killswitch_types::graph::{
    ApprovalDecision, KillSwitchGraphState, OperatorApprovalState, OrchestratorMode,
    StateCheckpointer,
};

use crate::checkpointer::DurableFileCheckpointer;
use crate::graph::{CompiledStateGraph, StateGraphBuilder};
use crate::nodes::{
    AdjudicateNode, ContainNode, CorrelateNode, DecideNode, IngestNode, LineageTriggerNode,
    MonitorNode, ReasonOllamaNode, RollbackNode, TerminalNode,
};
use crate::ollama::OllamaReasoningEngine;
use crate::state::{LifecycleStage, StepTransition};

/// Configuration for the KillSwitch Orchestrator.
#[derive(Debug, Clone)]
pub struct OrchestratorConfig {
    pub mode: OrchestratorMode,
    pub db_dir: Option<PathBuf>,
    pub consecutive_healthy_probes_required: usize,
    pub probe_interval_secs: u64,
    pub watchdog_max_secs: u64,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        Self {
            mode: OrchestratorMode::Autonomous,
            db_dir: None,
            consecutive_healthy_probes_required: 3,
            probe_interval_secs: 60,
            watchdog_max_secs: 1800,
        }
    }
}

/// The master orchestrator service coordinating the cyclic StateGraph.
pub struct KillSwitchOrchestrator {
    graph: Arc<CompiledStateGraph>,
    checkpointer: Arc<dyn StateCheckpointer>,
    active_state: Arc<RwLock<KillSwitchGraphState>>,
    current_stage: Arc<RwLock<LifecycleStage>>,
}

impl KillSwitchOrchestrator {
    /// Constructs a fully cross-wired `KillSwitchOrchestrator` using platform subsystems.
    pub fn new(
        config: OrchestratorConfig,
        containment: Arc<HostContainmentManager>,
        adjudicator: Arc<ZeroFalsePositiveAdjudicator>,
        lineage: Arc<EndpointLineageEngine>,
    ) -> Self {
        let storage_dir = config.db_dir.unwrap_or_else(|| {
            std::env::var("OSOOSI_DATABASE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."))
        });

        let checkpointer: Arc<dyn StateCheckpointer> =
            Arc::new(DurableFileCheckpointer::new(storage_dir).unwrap_or_else(|_| {
                let secure_temp = std::env::temp_dir().join(".killswitch_secure");
                let _ = std::fs::create_dir_all(&secure_temp);
                DurableFileCheckpointer::new(secure_temp).expect("tempdir checkpointer")
            }));

        let ollama = Arc::new(OllamaReasoningEngine::default());

        // Assemble standard 10-node StateGraph
        let builder = StateGraphBuilder::new()
            .add_node(LifecycleStage::Ingest, Arc::new(IngestNode))
            .add_node(LifecycleStage::Correlate, Arc::new(CorrelateNode::new(None)))
            .add_node(
                LifecycleStage::Adjudicate,
                Arc::new(AdjudicateNode::new(adjudicator.clone())),
            )
            .add_node(
                LifecycleStage::LineageTrigger,
                Arc::new(LineageTriggerNode::new(lineage.clone(), adjudicator.clone())),
            )
            .add_node(
                LifecycleStage::ReasonOllama,
                Arc::new(ReasonOllamaNode::new(ollama)),
            )
            .add_node(LifecycleStage::Decide, Arc::new(DecideNode))
            .add_node(
                LifecycleStage::Contain,
                Arc::new(ContainNode::new(containment.clone())),
            )
            .add_node(
                LifecycleStage::Monitor,
                Arc::new(MonitorNode::new(containment.clone())),
            )
            .add_node(
                LifecycleStage::Rollback,
                Arc::new(RollbackNode::new(containment)),
            )
            .add_node(
                LifecycleStage::Terminal,
                Arc::new(TerminalNode::new(Some(checkpointer.clone()))),
            )
            // Edges
            .add_edge(LifecycleStage::Ingest, LifecycleStage::Correlate)
            .add_edge(LifecycleStage::Correlate, LifecycleStage::Adjudicate)
            .add_edge(LifecycleStage::Adjudicate, LifecycleStage::LineageTrigger)
            .add_edge(LifecycleStage::LineageTrigger, LifecycleStage::ReasonOllama)
            .add_edge(LifecycleStage::ReasonOllama, LifecycleStage::Decide)
            // Conditional edge from Decide: if manual and unapproved -> pause/Terminal, else Contain
            .add_conditional_edge(
                LifecycleStage::Decide,
                Arc::new(|state| {
                    if state.mode == OrchestratorMode::Manual && state.operator_approval.is_none() {
                        LifecycleStage::Terminal
                    } else if state.aggregate_threat_score >= 0.85 || !state.active_threats.is_empty() {
                        LifecycleStage::Contain
                    } else {
                        LifecycleStage::Terminal
                    }
                }),
            )
            .add_edge(LifecycleStage::Contain, LifecycleStage::Monitor)
            // Conditional edge from Monitor: if 3 clean probes -> Rollback, else loop or Terminal
            .add_conditional_edge(
                LifecycleStage::Monitor,
                Arc::new(|state| {
                    if let Some(probe) = state.probe_results.last() {
                        if probe.eligible_for_early_rollback {
                            return LifecycleStage::Rollback;
                        }
                    }
                    LifecycleStage::Terminal
                }),
            )
            .add_edge(LifecycleStage::Rollback, LifecycleStage::Terminal)
            .set_checkpointer(checkpointer.clone())
            .set_entry_stage(LifecycleStage::Ingest);

        let graph = Arc::new(builder.compile());
        let incident_id = format!("inc-{}", uuid::Uuid::new_v4());
        let initial_state = KillSwitchGraphState::new(incident_id, config.mode);

        Self {
            graph,
            checkpointer,
            active_state: Arc::new(RwLock::new(initial_state)),
            current_stage: Arc::new(RwLock::new(LifecycleStage::Ingest)),
        }
    }

    /// Advances the orchestrator by a single discrete step.
    pub async fn step(&self) -> Result<StepTransition> {
        let mut state = self.active_state.write().await;
        let mut stage_guard = self.current_stage.write().await;
        let stage = *stage_guard;

        let transition = self.graph.step(&mut state, stage).await?;
        *stage_guard = if transition.is_terminal {
            LifecycleStage::Ingest
        } else {
            transition.to_stage
        };

        Ok(transition)
    }

    /// Runs the graph from the entry stage until pause or terminal.
    pub async fn run_incident_cycle(&self) -> Result<KillSwitchGraphState> {
        let mut state = self.active_state.write().await;
        let entry = self.graph.entry_stage;
        self.graph.run_until_pause_or_terminal(&mut state, entry).await?;
        Ok(state.clone())
    }

    /// Sets operating mode (Autonomous vs Manual).
    pub async fn set_mode(&self, mode: OrchestratorMode) {
        let mut state = self.active_state.write().await;
        state.mode = mode;
    }

    /// Retrieves a cloned snapshot of the active graph state.
    pub async fn get_state(&self) -> KillSwitchGraphState {
        self.active_state.read().await.clone()
    }

    /// Submits a threat candidate into the active incident.
    pub async fn submit_threat(&self, candidate: ThreatCandidate) -> Result<()> {
        let mut state = self.active_state.write().await;
        state.active_threats.push(candidate);
        if state.aggregate_threat_score < 0.85 {
            state.aggregate_threat_score = 0.85;
        }
        Ok(())
    }

    /// Submits human-in-the-loop operator approval to resume from manual pause.
    pub async fn submit_approval(&self, approval: OperatorApprovalState) -> Result<()> {
        let mut state = self.active_state.write().await;
        state.operator_approval = Some(approval);
        Ok(())
    }

    /// Access the underlying checkpointer.
    pub fn checkpointer(&self) -> Arc<dyn StateCheckpointer> {
        self.checkpointer.clone()
    }

    /// Evaluates the CAGE Policy Enforcement Point guard for the proposed action.
    pub fn evaluate_cage_guard(
        &self,
        state: &mut KillSwitchGraphState,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> std::result::Result<CageDecisionReceipt, KillSwitchError> {
        evaluate_cage_guard(state, tool_name, arguments)
    }

    /// Evaluates the CAGE Policy Enforcement Point guard against the active orchestrator state.
    pub async fn evaluate_active_cage_guard(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> std::result::Result<CageDecisionReceipt, KillSwitchError> {
        let mut state = self.active_state.write().await;
        evaluate_cage_guard(&mut state, tool_name, arguments)
    }
}

/// Policy Enforcement Point (PEP) evaluating CAGE 8-tier deterministic governance
/// before tool/agent invocations and actuation transitions.
pub fn evaluate_cage_guard(
    state: &mut KillSwitchGraphState,
    tool_name: &str,
    arguments: serde_json::Value,
) -> std::result::Result<CageDecisionReceipt, KillSwitchError> {
    let agent_id = arguments
        .get("agent_id")
        .and_then(|v| v.as_str())
        .or_else(|| state.metadata.get("cage_agent_id").map(|s| s.as_str()))
        .or_else(|| state.metadata.get("agent_id").map(|s| s.as_str()))
        .unwrap_or("killswitch-orchestrator")
        .to_string();

    let role = arguments
        .get("role")
        .and_then(|v| v.as_str())
        .or_else(|| state.metadata.get("cage_role").map(|s| s.as_str()))
        .or_else(|| state.metadata.get("agent_role").map(|s| s.as_str()))
        .unwrap_or_else(|| {
            if tool_name == "query_ollama_reasoning" {
                "forensic_analyst"
            } else {
                "containment_orchestrator"
            }
        })
        .to_string();

    let confidence_score = arguments
        .get("confidence_score")
        .and_then(|v| v.as_f64())
        .or_else(|| {
            state
                .metadata
                .get("cage_confidence_score")
                .and_then(|s| s.parse::<f64>().ok())
        })
        .or(if state.aggregate_threat_score > 0.0 {
            Some(state.aggregate_threat_score as f64)
        } else {
            None
        });

    let amount_usd = arguments
        .get("amount_usd")
        .and_then(|v| v.as_f64())
        .or_else(|| {
            state
                .metadata
                .get("cage_amount_usd")
                .and_then(|s| s.parse::<f64>().ok())
        });

    let dose_mg = arguments
        .get("dose_mg")
        .and_then(|v| v.as_f64())
        .or_else(|| {
            state
                .metadata
                .get("cage_dose_mg")
                .and_then(|s| s.parse::<f64>().ok())
        });

    let warrant_token: Option<CageWarrantToken> = arguments
        .get("warrant_token")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .or_else(|| {
            state
                .metadata
                .get("cage_warrant_token")
                .and_then(|s| serde_json::from_str(s).ok())
        });

    let human_approval: Option<HitlConsensusApproval> = arguments
        .get("human_approval")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .or_else(|| {
            state
                .metadata
                .get("cage_human_approval")
                .and_then(|s| serde_json::from_str(s).ok())
        })
        .or_else(|| {
            state.operator_approval.as_ref().map(|app| {
                let rationale = app.comments.clone().unwrap_or_else(|| {
                    if !app.confirmation_token.trim().is_empty() {
                        format!("Operator confirmed via token '{}'", app.confirmation_token)
                    } else {
                        String::new()
                    }
                });
                HitlConsensusApproval {
                    operator_id: app.operator_id.clone(),
                    is_approved: matches!(
                        app.decision,
                        ApprovalDecision::Approved | ApprovalDecision::AutoApproved
                    ),
                    rationale,
                    approved_at_ms: chrono::Utc::now().timestamp_millis().max(0) as u64,
                    signature_hex: None,
                }
            })
        });

    let mut effective_args = arguments.clone();
    if let Some(confab) = state.metadata.get("cage_confabulation") {
        if let Some(obj) = effective_args.as_object_mut() {
            obj.insert("claim".to_string(), serde_json::Value::String(confab.clone()));
        }
    }
    if let Some(override_args) = state.metadata.get("cage_arguments") {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(override_args) {
            if let Some(obj) = effective_args.as_object_mut() {
                if let Some(over_obj) = val.as_object() {
                    for (k, v) in over_obj {
                        obj.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }

    let mut ctx = serde_json::json!({
        "incident_id": state.incident_id,
        "mode": format!("{:?}", state.mode),
        "active_threats_count": state.active_threats.len(),
        "isolated": state.containment_status.isolated,
        "aggregate_threat_score": state.aggregate_threat_score,
    });
    if let Some(arg_ctx) = arguments.get("context").and_then(|c| c.as_object()) {
        if let Some(obj) = ctx.as_object_mut() {
            for (k, v) in arg_ctx {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    if let Some(meta_ctx_str) = state.metadata.get("cage_context") {
        if let Ok(meta_ctx) = serde_json::from_str::<serde_json::Value>(meta_ctx_str) {
            if let Some(arg_ctx) = meta_ctx.as_object() {
                if let Some(obj) = ctx.as_object_mut() {
                    for (k, v) in arg_ctx {
                        obj.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }

    let req = CageEvaluationRequest {
        agent_id,
        role,
        tool_name: tool_name.to_string(),
        arguments: effective_args,
        confidence_score,
        amount_usd,
        dose_mg,
        warrant_token,
        human_approval,
        context: Some(ctx),
    };

    let kernel = global_cage_kernel();
    let resp = kernel.evaluate(&req);

    match resp.verdict {
        CageVerdict::Clear => {
            state.metadata.insert(
                "cage_receipt_digest".to_string(),
                resp.receipt.decision_digest.clone(),
            );
            state.metadata.insert(
                "cage_substrate_digest".to_string(),
                resp.receipt.substrate_digest.clone(),
            );
            state.metadata.insert(
                "cage_signature".to_string(),
                resp.receipt.receipt_signature.clone(),
            );
            state.metadata.insert(
                "cage_decision_digest".to_string(),
                resp.receipt.decision_digest.clone(),
            );
            state.metadata.insert(
                "cage_receipt_id".to_string(),
                resp.receipt.receipt_id.clone(),
            );
            state.metadata.insert("cage_verdict".to_string(), "Clear".to_string());
            state.metadata.insert("cage_last_verdict".to_string(), "Clear".to_string());
            state.metadata.insert("cage_rule_id".to_string(), resp.rule_id.clone());
            state.metadata.insert("cage_last_rule_id".to_string(), resp.rule_id);
            state.metadata.insert("cage_tier".to_string(), format!("{:?}", resp.tier));
            state.metadata.insert("cage_last_tier".to_string(), format!("{:?}", resp.tier));

            Ok(resp.receipt)
        }
        CageVerdict::Refuse => {
            let reason = resp.receipt.refusal_reason.clone().unwrap_or_else(|| {
                resp.error_message
                    .clone()
                    .unwrap_or_else(|| "CAGE policy refusal".to_string())
            });

            state.metadata.insert("cage_refusal".to_string(), reason.clone());
            state.metadata.insert(
                "cage_receipt_digest".to_string(),
                resp.receipt.decision_digest.clone(),
            );
            state.metadata.insert(
                "cage_decision_digest".to_string(),
                resp.receipt.decision_digest.clone(),
            );
            state.metadata.insert(
                "cage_substrate_digest".to_string(),
                resp.receipt.substrate_digest.clone(),
            );
            state.metadata.insert(
                "cage_signature".to_string(),
                resp.receipt.receipt_signature.clone(),
            );
            state.metadata.insert(
                "cage_receipt_id".to_string(),
                resp.receipt.receipt_id.clone(),
            );
            state.metadata.insert("cage_verdict".to_string(), "Refuse".to_string());
            state.metadata.insert("cage_last_verdict".to_string(), "Refuse".to_string());
            state.metadata.insert("cage_rule_id".to_string(), resp.rule_id.clone());
            state.metadata.insert("cage_last_rule_id".to_string(), resp.rule_id.clone());
            state.metadata.insert("cage_tier".to_string(), format!("{:?}", resp.tier));
            state.metadata.insert("cage_last_tier".to_string(), format!("{:?}", resp.tier));

            Err(KillSwitchError::GraphHalted(format!(
                "CAGE PEP refused action '{}' by rule '{}' at {:?}: {}",
                tool_name, resp.rule_id, resp.tier, reason
            )))
        }
    }
}
