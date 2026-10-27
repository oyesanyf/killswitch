//! # Pure Rust Cyclic StateGraph Engine
//!
//! Implements a cyclic directed execution graph over `KillSwitchGraphState` with
//! conditional routing, dynamic checkpointer integration, and BLAKE3 trace verification.

use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;

use killswitch_types::errors::{KillSwitchError, Result};
use killswitch_types::graph::{GraphNodeOutput, KillSwitchGraphState, OrchestratorMode, StateCheckpointer};

use crate::state::{LifecycleStage, StepTransition};

pub type RoutingFn = Arc<dyn Fn(&KillSwitchGraphState) -> LifecycleStage + Send + Sync>;

/// Asynchronous lifecycle node trait implemented by each discrete graph node.
#[async_trait]
pub trait LifecycleNode: Send + Sync {
    fn stage(&self) -> LifecycleStage;
    async fn execute(&self, state: &mut KillSwitchGraphState) -> Result<GraphNodeOutput>;
}

/// Builder for constructing a cyclic StateGraph.
pub struct StateGraphBuilder {
    nodes: HashMap<LifecycleStage, Arc<dyn LifecycleNode>>,
    direct_edges: HashMap<LifecycleStage, LifecycleStage>,
    conditional_edges: HashMap<LifecycleStage, RoutingFn>,
    entry_stage: LifecycleStage,
    checkpointer: Option<Arc<dyn StateCheckpointer>>,
    max_cycle_depth: usize,
}

impl Default for StateGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl StateGraphBuilder {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            direct_edges: HashMap::new(),
            conditional_edges: HashMap::new(),
            entry_stage: LifecycleStage::Ingest,
            checkpointer: None,
            max_cycle_depth: 50,
        }
    }

    pub fn add_node(mut self, stage: LifecycleStage, node: Arc<dyn LifecycleNode>) -> Self {
        self.nodes.insert(stage, node);
        self
    }

    pub fn add_edge(mut self, from: LifecycleStage, to: LifecycleStage) -> Self {
        self.direct_edges.insert(from, to);
        self
    }

    pub fn add_conditional_edge(mut self, from: LifecycleStage, router: RoutingFn) -> Self {
        self.conditional_edges.insert(from, router);
        self
    }

    pub fn set_entry_stage(mut self, stage: LifecycleStage) -> Self {
        self.entry_stage = stage;
        self
    }

    pub fn set_checkpointer(mut self, checkpointer: Arc<dyn StateCheckpointer>) -> Self {
        self.checkpointer = Some(checkpointer);
        self
    }

    pub fn set_max_cycle_depth(mut self, depth: usize) -> Self {
        self.max_cycle_depth = depth;
        self
    }

    pub fn compile(self) -> CompiledStateGraph {
        CompiledStateGraph {
            nodes: self.nodes,
            direct_edges: self.direct_edges,
            conditional_edges: self.conditional_edges,
            entry_stage: self.entry_stage,
            checkpointer: self.checkpointer,
            max_cycle_depth: self.max_cycle_depth,
        }
    }
}

/// Fully compiled, thread-safe executable StateGraph.
pub struct CompiledStateGraph {
    nodes: HashMap<LifecycleStage, Arc<dyn LifecycleNode>>,
    direct_edges: HashMap<LifecycleStage, LifecycleStage>,
    conditional_edges: HashMap<LifecycleStage, RoutingFn>,
    pub entry_stage: LifecycleStage,
    checkpointer: Option<Arc<dyn StateCheckpointer>>,
    max_cycle_depth: usize,
}

impl CompiledStateGraph {
    /// Executes a single discrete transition in the LangGraph cycle.
    pub async fn step(
        &self,
        state: &mut KillSwitchGraphState,
        current_stage: LifecycleStage,
    ) -> Result<StepTransition> {
        let node = self.nodes.get(&current_stage).ok_or_else(|| {
            KillSwitchError::GraphHalted(format!(
                "Node '{:?}' not found in compiled graph registry",
                current_stage
            ))
        })?;

        let start_time = std::time::Instant::now();
        let input_bytes = serde_json::to_vec(&state).unwrap_or_default();
        let input_digest = blake3::hash(&input_bytes).to_hex().to_string();

        // Execute node logic
        let output = node.execute(state).await?;

        // Determine next stage
        let next_stage = if let Some(router) = self.conditional_edges.get(&current_stage) {
            router(state)
        } else if let Some(&next) = self.direct_edges.get(&current_stage) {
            next
        } else {
            LifecycleStage::Terminal
        };

        let duration_ms = start_time.elapsed().as_millis() as u64;
        let output_bytes = serde_json::to_vec(&output).unwrap_or_default();
        let output_digest = blake3::hash(&output_bytes).to_hex().to_string();

        // Record immutable BLAKE3-chained execution step
        state.record_execution_step(
            current_stage.to_graph_node_id(),
            input_digest,
            output_digest,
            duration_ms,
            serde_json::to_value(&output).unwrap_or_default(),
        );

        // Commit checkpoint if checkpointer is configured
        if let Some(cp) = &self.checkpointer {
            cp.save_checkpoint(state).await?;
        }

        let is_paused = matches!(current_stage, LifecycleStage::Decide)
            && state.mode == OrchestratorMode::Manual
            && state.operator_approval.is_none();

        let is_terminal = matches!(next_stage, LifecycleStage::Terminal);

        Ok(StepTransition {
            from_stage: current_stage,
            to_stage: next_stage,
            duration_ms,
            threat_score: state.aggregate_threat_score,
            is_isolated: state.containment_status.isolated,
            is_paused,
            is_terminal,
            summary: output.summary,
        })
    }

    /// Runs the cyclic state graph until Terminal node or HITL pause.
    pub async fn run_until_pause_or_terminal(
        &self,
        state: &mut KillSwitchGraphState,
        mut current_stage: LifecycleStage,
    ) -> Result<LifecycleStage> {
        let mut steps = 0;
        while steps < self.max_cycle_depth {
            let transition = self.step(state, current_stage).await?;
            if transition.is_paused || transition.is_terminal {
                return Ok(transition.to_stage);
            }
            current_stage = transition.to_stage;
            steps += 1;
        }

        Err(KillSwitchError::GraphHalted(format!(
            "LangGraph exceeded maximum cycle recursion limit of {} steps",
            self.max_cycle_depth
        )))
    }
}
