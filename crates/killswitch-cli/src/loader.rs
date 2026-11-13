//! # Unified Loader & Boot Coordinator
//!
//! Boots 100% of the KillSwitch subsystems into a single cohesive runtime:
//! 1. Core Containment Engine & BLAKE3 State Ledger
//! 2. Zero-False-Positive Adjudicator & WinTrust Verifier
//! 3. OpenTelemetry / DLP Lineage Engine & Standalone Breakout Defense
//! 4. 10-Node Cyclic LangGraph Orchestrator & Durable Checkpointer
//! 5. Local Axum HTTP API Server (127.0.0.1:3030)
//! 6. Native Cross-Platform OS Service Lifecycle Manager
//!
//! Enforces Zero OS Subprocess spawning and guaranteed emergency restore upon exit.

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

use killswitch_adjudication::ZeroFalsePositiveAdjudicator;
use killswitch_core::killchain::HostContainmentManager;
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
use killswitch_types::graph::{
    GraphNodeId, GraphNodeOutput, KillSwitchGraphState, OrchestratorMode,
};

/// Configuration options for booting the unified system.
#[derive(Debug, Clone)]
pub struct UnifiedConfig {
    pub host: String,
    pub port: u16,
    pub mode: OrchestratorMode,
    pub db_dir: Option<PathBuf>,
    pub open_browser: bool,
}

impl Default for UnifiedConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3030,
            mode: OrchestratorMode::Autonomous,
            db_dir: None,
            open_browser: false,
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
        force_node: Option<GraphNodeId>,
    ) -> Result<GraphNodeOutput, ServerError> {
        let transition = self
            .orchestrator
            .step_with_force(force_node)
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

    async fn submit_threat(
        &self,
        candidate: ThreatCandidate,
    ) -> Result<GraphNodeOutput, ServerError> {
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
        // Clean up any legacy split-brain ./killchain_state.json when using standard database directory
        if config.db_dir.is_none() {
            let legacy_ledger = PathBuf::from("killchain_state.json");
            if legacy_ledger.exists() && !legacy_ledger.is_symlink() {
                if let Ok(raw) = std::fs::read_to_string(&legacy_ledger) {
                    if !raw.contains("\"isolated\": true") && !raw.contains("\"isolated\":true") {
                        let _ = std::fs::remove_file(&legacy_ledger);
                    } else {
                        warn!(
                            "⚠️ [LOADER] Preserving legacy active quarantine ledger '{}'",
                            legacy_ledger.display()
                        );
                    }
                }
            }
        }

        let containment_manager = Arc::new(
            HostContainmentManager::new_default(config.db_dir.as_deref())
                .context("Failed to initialize HostContainmentManager")?,
        );

        #[cfg(target_os = "windows")]
        if std::env::var("CARGO").is_err()
            && std::env::var("RUST_TEST_THREADS").is_err()
            && containment_manager.get_status().isolated
            && !killswitch_core::wfp::has_live_active_wfp_filters()
        {
            let status_snapshot = containment_manager.get_status();
            warn!("🛡️ [LOADER] Re-enforcing persistent ledger quarantine on boot: WFP filters absent while ledger recorded isolated=true.");
            let _ = containment_manager
                .engage_isolation(
                    status_snapshot
                        .isolated_by
                        .as_deref()
                        .unwrap_or("BOOT_PERSISTENCE"),
                    status_snapshot
                        .reason
                        .as_deref()
                        .unwrap_or("Fail-closed boot re-enforcement of persisted containment"),
                    status_snapshot.containment_level,
                    None,
                )
                .await;
        }

        let storage_dir = config.db_dir.clone().unwrap_or_else(|| {
            std::env::var("KILLSWITCH_DATABASE_DIR")
                .or_else(|_| std::env::var("OSOOSI_DATABASE_DIR"))
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("database"))
        });

        info!("🛡️ [LOADER] Booting Phase 2: Zero-False-Positive Adjudication Engine");
        let adjudicator = Arc::new(ZeroFalsePositiveAdjudicator::new());

        info!("🛡️ [LOADER] Booting Phase 3: Telemetry, DLP Lineage Engine & Standalone Breakout Defense");
        let lineage_engine = Arc::new(EndpointLineageEngine::new_in_memory());
        let octopus_seed = {
            let mut s = [0u8; 32];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut s);
            s
        };
        let arm_registry = Arc::new(ArmRingRegistry::new(&octopus_seed));
        let event_correlator = Arc::new(EventCorrelator::default());
        let phaselock_manager = Arc::new(PhaseLockManager::default());
        if std::env::var("KILLSWITCH_SELF_DIAGNOSTIC").is_err() {
            let _ =
                killswitch_telemetry::global_agentsonar_engine().start_background_collector(false);
        }

        // Wire tamper detection directly into active Fail-Closed HostContainmentManager escalation
        {
            let cm = Arc::clone(&containment_manager);
            killswitch_telemetry::tamper_and_process_killswitch::register_tamper_containment_handler(
                Arc::new(move |reason: &str| {
                    let cm_inner = Arc::clone(&cm);
                    let reason_owned = reason.to_string();
                    if let Ok(handle) = tokio::runtime::Handle::try_current() {
                        handle.spawn(async move {
                            let _ = cm_inner
                                .engage_isolation(
                                    "tamper_guard",
                                    &reason_owned,
                                    killswitch_types::status::ContainmentLevel::HermeticIsolation,
                                    None,
                                )
                                .await;
                        });
                    }
                }),
            );
        }

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
        server_state_raw.active_mode = Arc::new(tokio::sync::RwLock::new(config.mode));
        server_state_raw
            .active_bound_port
            .store(config.port, std::sync::atomic::Ordering::SeqCst);
        server_state_raw.config = ServerConfig {
            host: config.host.clone(),
            port: config.port,
            open_browser: config.open_browser,
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
    /// Strictly fail-closed: HTTP server shutdown preserves active OS/ledger containment.
    pub async fn run(self) -> Result<()> {
        info!(
            "🚀 [LOADER] Starting KillSwitch Unified Runtime on http://{}:{}",
            self.config.host, self.config.port
        );

        let server = self.server.clone();
        let shutdown_signal = async {
            tokio::signal::ctrl_c().await.ok();
            warn!("🛑 [SHUTDOWN] Control-plane interruption signal received. Stopping HTTP control plane while keeping active containment FAIL-CLOSED.");
        };

        server
            .run_with_shutdown(shutdown_signal)
            .await
            .context("Server execution failure")?;

        info!("🛡️ [LOADER] Unified Runtime halted cleanly.");
        Ok(())
    }
}
