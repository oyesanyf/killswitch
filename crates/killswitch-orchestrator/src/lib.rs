//! # `killswitch-orchestrator`
//!
//! LangGraph Stateful Agent Orchestrator for the Standalone Rust KillSwitch Security Agent.
//!
//! Implements:
//! - 10-node cyclic execution lifecycle (`LifecycleStage`, `CompiledStateGraph`, `StateGraphBuilder`)
//! - BLAKE3-chained cryptographic trace validation (`ExecutionStep`, `StateCheckpointer`)
//! - Durable atomic state checkpointer with tamper resistance (`DurableFileCheckpointer`)
//! - Dynamic Available Memory Law with 400ms timeout for local Ollama reasoning (`OllamaReasoningEngine`)
//! - Autonomous DLP Lineage trigger evaluator (`LineageTriggerEvaluator`)
//! - High-level orchestrator service coordinator (`KillSwitchOrchestrator`)

pub mod checkpointer;
pub mod engine;
pub mod graph;
pub mod lineage_trigger;
pub mod nodes;
pub mod ollama;
pub mod state;

// Re-exports
pub use checkpointer::DurableFileCheckpointer;
pub use engine::{KillSwitchOrchestrator, OrchestratorConfig};
pub use graph::{CompiledStateGraph, LifecycleNode, RoutingFn, StateGraphBuilder};
pub use lineage_trigger::LineageTriggerEvaluator;
pub use ollama::{OllamaReasoningEngine, OllamaReasoningResult};
pub use state::{LifecycleStage, StepTransition};
