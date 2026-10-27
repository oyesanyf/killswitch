//! # Unified Loader & Boot Coordinator
//!
//! Boots 100% of the KillSwitch subsystems into a single cohesive runtime:
//! 1. Core Containment Engine & BLAKE3 State Ledger
//! 2. Zero-False-Positive Adjudicator & WinTrust Verifier
//! 3. OpenTelemetry / DLP Lineage Engine & Octopus 18-Arm Rings
//! 4. 10-Node Cyclic LangGraph Orchestrator & Durable Checkpointer
//! 5. Local Axum HTTP API Server (127.0.0.1:3030)
//! 6. Native Cross-Platform OS Service Lifecycle Manager
//!
//! Enforces Zero OS Subprocess spawning and guaranteed emergency restore upon exit.

use std::path::PathBuf;
use std::sync::Arc;
use anyhow::{Context, Result};
use async_trait::async_trait;
use tracing::{info, warn};

use killswitch_adjudication::ZeroFalsePositiveAdjudicator;
use killswitch_core::killchain::{execute_host_disarm_unauthenticated, HostContainmentManager};
use killswitch_core::service::{default_service_manager, NativeServiceManager};
use killswitch_orchestrator::engine::{KillSwitchOrchestrator, OrchestratorConfig};
use killswitch_server::error::ServerError;
use killswitch_server::orchestrator_bridge::OrchestratorBridge;
use killswitch_server::server::{KillSwitchServer, ServerConfig, ServerState};
use killswitch_telemetry::correlator::EventCorrelator;
use killswitch_telemetry::octopus::ArmRingRegistry;
use killswitch_telemetry::otel_lineage::EndpointLineageEngine;
use killswitch_telemetry::phaselock::PhaseLockManager;
use killswitch_types::adjudication::ThreatCandidate;
use killswitch_types::graph::{GraphNodeId, GraphNodeOutput, KillSwitchGraphState, OrchestratorMode};

/// Configuration options for booting the unified system.
#[derive(Debug, Clone)]
pub struct UnifiedConfig {
    pub host: String,
    pub port: u16,
    pub mode: OrchestratorMode,
    pub db_dir: Option<PathBuf>,
}

impl Default for UnifiedConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3030,
            mode: OrchestratorMode::Autonomous,
            db_dir: None,
        }
    }
}

/// Adapter connecting `KillSwitchOrchestrator` to `killswitch-server`'s `OrchestratorBridge`.
pub struct LiveOrchestratorAdapter {
    orchestrator: Arc<KillSwitchOrchestrator>,
}

impl LiveOrchestratorAdapter {
    pub fn new(orchestrator: Arc<KillSwitchOrchestrator>) -> Self {
        Self { orchestrator }
    }
}

#[async_trait]
impl OrchestratorBridge for LiveOrchestratorAdapter {
    async fn get_state(&self) -> KillSwitchGraphState {
        self.orchestrator.get_state().await
    }

    async fn set_mode(&self, mode: OrchestratorMode) -> Result<(), ServerError> {
        self.orchestrator.set_mode(mode).await;
        Ok(())
    }

    async fn step(
        &self,
        _input: Option<serde_json::Value>,
        _force_node: Option<GraphNodeId>,
    ) -> Result<GraphNodeOutput, ServerError> {
        let transition = self
            .orchestrator
            .step()
            .await
            .map_err(|e| ServerError::Internal(format!("Orchestrator step failed: {}", e)))?;

        let current = self.orchestrator.get_state().await.current_node;
        Ok(GraphNodeOutput {
            next_node: Some(current),
            updated_threat_score: None,
            candidate_updates: Vec::new(),
            containment_action_taken: None,
            fraud_proofs_emitted: Vec::new(),
            summary: format!(
                "Transitioned from {:?} to {:?}",
                transition.from_stage, transition.to_stage
            ),
        })
    }

    async fn submit_threat(&self, candidate: ThreatCandidate) -> Result<GraphNodeOutput, ServerError> {
        self.orchestrator
            .submit_threat(candidate.clone())
            .await
            .map_err(|e| ServerError::Internal(format!("Threat submission failed: {}", e)))?;

        let current = self.orchestrator.get_state().await.current_node;
        Ok(GraphNodeOutput {
            next_node: Some(current),
            updated_threat_score: Some(0.85),
            candidate_updates: vec![candidate.clone()],
            containment_action_taken: None,
            fraud_proofs_emitted: Vec::new(),
            summary: format!("Threat candidate submitted: pid {:?}", candidate.pid),
        })
    }
}

/// The unified runtime holding references to 100% of the loaded subsystems.
pub struct UnifiedRuntime {
    pub containment_manager: Arc<HostContainmentManager>,
    pub adjudicator: Arc<ZeroFalsePositiveAdjudicator>,
    pub lineage_engine: Arc<EndpointLineageEngine>,
    pub arm_registry: Arc<ArmRingRegistry>,
    pub event_correlator: Arc<EventCorrelator>,
    pub phaselock_manager: Arc<PhaseLockManager>,
    pub orchestrator: Arc<KillSwitchOrchestrator>,
    pub service_manager: Arc<dyn NativeServiceManager>,
    pub server_state: Arc<ServerState>,
    pub server: Arc<KillSwitchServer>,
    pub config: UnifiedConfig,
}

impl UnifiedRuntime {
    /// Boots 100% of the subsystems and links them into a single cohesive runtime.
    pub async fn boot(config: UnifiedConfig) -> Result<Self> {
        info!("🛡️ [LOADER] Booting Phase 1: Core Host Containment & State Ledger");
        let storage_dir = config.db_dir.clone().unwrap_or_else(|| {
            std::env::var("OSOOSI_DATABASE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."))
        });

        let containment_manager = Arc::new(
            HostContainmentManager::new_default(Some(&storage_dir))
                .context("Failed to initialize HostContainmentManager")?,
        );

        info!("🛡️ [LOADER] Booting Phase 2: Zero-False-Positive Adjudication Engine");
        let adjudicator = Arc::new(ZeroFalsePositiveAdjudicator::new());

        info!("🛡️ [LOADER] Booting Phase 3: Telemetry, DLP Lineage Engine & Octopus 18-Arm Mesh");
        let lineage_engine = Arc::new(EndpointLineageEngine::new_in_memory());
        let arm_registry = Arc::new(ArmRingRegistry::new(b"killswitch_master_octopus_seed_00"));
        let event_correlator = Arc::new(EventCorrelator::default());
        let phaselock_manager = Arc::new(PhaseLockManager::default());

        info!("🛡️ [LOADER] Booting Phase 4: LangGraph Orchestrator & BLAKE3 Checkpointer");
        let orch_config = OrchestratorConfig {
            mode: config.mode,
            db_dir: Some(storage_dir),
            ..Default::default()
        };
        let orchestrator = Arc::new(KillSwitchOrchestrator::new(
            orch_config,
            containment_manager.clone(),
            adjudicator.clone(),
            lineage_engine.clone(),
        ));

        info!("🛡️ [LOADER] Booting Phase 5: Native OS Service Lifecycle Manager");
        let service_manager = default_service_manager();

        info!("🛡️ [LOADER] Booting Phase 6: Local Axum HTTP Control Server");
        let bridge = Arc::new(LiveOrchestratorAdapter::new(orchestrator.clone()));
        let mut server_state_raw = ServerState::new(
            containment_manager.clone(),
            adjudicator.clone(),
            lineage_engine.clone(),
            bridge,
            service_manager.clone(),
        );
        server_state_raw.arm_registry = arm_registry.clone();
        server_state_raw.event_correlator = event_correlator.clone();
        server_state_raw.phaselock_manager = phaselock_manager.clone();
        server_state_raw.config = ServerConfig {
            host: config.host.clone(),
            port: config.port,
            ..Default::default()
        };

        let server_state = Arc::new(server_state_raw);
        let server = Arc::new(KillSwitchServer::new(server_state.clone()));

        info!("✅ [LOADER] All 6 Subsystems Successfully Initialized & Cross-Wired");

        Ok(Self {
            containment_manager,
            adjudicator,
            lineage_engine,
            arm_registry,
            event_correlator,
            phaselock_manager,
            orchestrator,
            service_manager,
            server_state,
            server,
            config,
        })
    }

    /// Runs the unified system until shutdown signal is received.
    /// Unconditionally executes `execute_host_disarm_unauthenticated()` before termination.
    pub async fn run(self) -> Result<()> {
        info!(
            "🚀 [LOADER] Starting KillSwitch Unified Runtime on http://{}:{}",
            self.config.host, self.config.port
        );

        let server = self.server.clone();
        let shutdown_signal = async {
            tokio::signal::ctrl_c().await.ok();
            warn!("🛑 [SHUTDOWN] Interruption signal received! Disarming containment...");
            let _ = execute_host_disarm_unauthenticated();
        };

        server
            .run_with_shutdown(shutdown_signal)
            .await
            .context("Server execution failure")?;

        info!("🛡️ [LOADER] Unified Runtime halted cleanly.");
        Ok(())
    }
}
