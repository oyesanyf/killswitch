//! # High-Level Orchestrator Service Coordinator
//!
//! Encapsulates the StateGraph, durable checkpointer, and active incident state.

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use killswitch_adjudication::ZeroFalsePositiveAdjudicator;
use killswitch_core::killchain::HostContainmentManager;
use killswitch_telemetry::otel_lineage::EndpointLineageEngine;
use killswitch_types::adjudication::ThreatCandidate;
use killswitch_types::errors::Result;
use killswitch_types::graph::{
    KillSwitchGraphState, OperatorApprovalState, OrchestratorMode, StateCheckpointer,
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
}
