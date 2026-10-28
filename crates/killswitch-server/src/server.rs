//! # Server Lifecycle, Configuration & Loopback Binding (Port 3030)
//!
//! Enforces loopback and control port 3030 preservation during full network containment.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::info;

use killswitch_adjudication::ZeroFalsePositiveAdjudicator;
use killswitch_core::killchain::HostContainmentManager;
use killswitch_core::service::{default_service_manager, NativeServiceManager};
use killswitch_telemetry::correlator::EventCorrelator;
use killswitch_telemetry::octopus::ArmRingRegistry;
use killswitch_telemetry::otel_lineage::EndpointLineageEngine;
use killswitch_telemetry::phaselock::PhaseLockManager;
use killswitch_types::graph::OrchestratorMode;

use crate::error::ServerError;
use crate::orchestrator_bridge::{InMemoryOrchestratorBridge, OrchestratorBridge};
use crate::routes::build_router;

/// Configuration for local Axum HTTP control server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub max_body_bytes: usize,
    pub request_timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3030,
            max_body_bytes: 2 * 1024 * 1024, // 2 MB
            request_timeout_secs: 30,
        }
    }
}

/// Shared application state injected across all HTTP handlers.
#[derive(Clone)]
pub struct ServerState {
    pub containment_manager: Arc<HostContainmentManager>,
    pub adjudicator: Arc<ZeroFalsePositiveAdjudicator>,
    pub lineage_engine: Arc<EndpointLineageEngine>,
    pub arm_registry: Arc<ArmRingRegistry>,
    pub event_correlator: Arc<EventCorrelator>,
    pub phaselock_manager: Arc<PhaseLockManager>,
    pub service_manager: Arc<dyn NativeServiceManager>,
    pub orchestrator_bridge: Arc<dyn OrchestratorBridge>,
    pub start_time: Instant,
    pub active_mode: Arc<RwLock<OrchestratorMode>>,
    pub last_trigger_cause: Arc<RwLock<Option<(String, String, String)>>>,
    pub peers_enabled: Arc<std::sync::atomic::AtomicBool>,
    pub fprime_supervisor: Arc<killswitch_core::fprime::FPrimeSupervisor>,
    pub config: ServerConfig,
}

pub type AppState = ServerState;

impl ServerState {
    pub fn new(
        containment_manager: Arc<HostContainmentManager>,
        adjudicator: Arc<ZeroFalsePositiveAdjudicator>,
        lineage_engine: Arc<EndpointLineageEngine>,
        orchestrator_bridge: Arc<dyn OrchestratorBridge>,
        service_manager: Arc<dyn NativeServiceManager>,
    ) -> Self {
        Self {
            containment_manager,
            adjudicator,
            lineage_engine,
            arm_registry: Arc::new(ArmRingRegistry::new(b"killswitch_master_octopus_seed_00")),
            event_correlator: Arc::new(EventCorrelator::default()),
            phaselock_manager: Arc::new(PhaseLockManager::default()),
            service_manager,
            orchestrator_bridge,
            start_time: Instant::now(),
            active_mode: Arc::new(RwLock::new(OrchestratorMode::Autonomous)),
            last_trigger_cause: Arc::new(RwLock::new(None)),
            peers_enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            fprime_supervisor: Arc::new(killswitch_core::fprime::FPrimeSupervisor::new()),
            config: ServerConfig::default(),
        }
    }

    pub fn with_defaults(containment_manager: Arc<HostContainmentManager>) -> Self {
        let adjudicator = Arc::new(ZeroFalsePositiveAdjudicator::new());
        let lineage_engine = Arc::new(EndpointLineageEngine::new_in_memory());
        let orchestrator_bridge = Arc::new(InMemoryOrchestratorBridge::default());
        let service_manager = default_service_manager();
        Self::new(containment_manager, adjudicator, lineage_engine, orchestrator_bridge, service_manager)
    }
}

/// HTTP Server wrapper.
pub struct KillSwitchServer {
    state: Arc<ServerState>,
}

impl KillSwitchServer {
    pub fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }

    /// Binds to configured IP and port (default 127.0.0.1:3030) with automatic port fallback
    /// if the requested port is already in use, and starts the Axum HTTP & WebUI server.
    pub async fn run_with_shutdown(
        &self,
        shutdown_signal: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), ServerError> {
        let host = self.state.config.host.clone();
        let requested_port = self.state.config.port;

        let mut candidate_ports: Vec<u16> = vec![requested_port];
        for p in (requested_port.saturating_add(1))..=(requested_port.saturating_add(30)) {
            if !candidate_ports.contains(&p) {
                candidate_ports.push(p);
            }
        }
        for p in 4040..=4050 {
            if !candidate_ports.contains(&p) {
                candidate_ports.push(p);
            }
        }
        candidate_ports.push(0); // Final OS-assigned ephemeral fallback

        let mut bound_listener: Option<TcpListener> = None;
        let mut actual_addr: Option<SocketAddr> = None;

        for port in candidate_ports {
            let addr: SocketAddr = format!("{}:{}", host, port)
                .parse()
                .map_err(|e| ServerError::Validation(format!("Invalid socket address: {}", e)))?;

            // On Windows, another process bound to 0.0.0.0:<port> or [::]:<port> may still allow
            // binding 127.0.0.1:<port> while intercepting traffic. Probe first when port != 0.
            if port != 0 {
                let probe_busy = tokio::time::timeout(
                    std::time::Duration::from_millis(120),
                    tokio::net::TcpStream::connect(addr),
                )
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);

                if probe_busy {
                    tracing::warn!(
                        "⚠️ [KILLSWITCH-SERVER] Port {} is already occupied by an active listener; trying next port...",
                        port
                    );
                    continue;
                }
            }

            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    let local = listener.local_addr().unwrap_or(addr);
                    bound_listener = Some(listener);
                    actual_addr = Some(local);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                    tracing::warn!(
                        "⚠️ [KILLSWITCH-SERVER] Port {} is in use (AddrInUse); trying next port...",
                        port
                    );
                    continue;
                }
                Err(e) => {
                    return Err(ServerError::Internal(format!("Failed to bind to {}: {}", addr, e)));
                }
            }
        }

        let listener = bound_listener.ok_or(ServerError::PortInUse(requested_port))?;
        let addr = actual_addr.unwrap();
        let bound_port = addr.port();

        if bound_port != requested_port {
            println!(
                "⚠️  [KILLSWITCH-SERVER] Port {} was in use; automatically bound to fallback port {}",
                requested_port, bound_port
            );
        }

        // Persist the active port so CLI subcommands (`killswitch.exe status/isolate/restore`) can auto-discover it
        let _ = std::fs::write("active_port.txt", bound_port.to_string());
        let _ = std::fs::write(
            std::env::temp_dir().join("killswitch_active_port.txt"),
            bound_port.to_string(),
        );

        println!("================================================================================");
        println!("🌐  KILLSWITCH WEBUI DASHBOARD READY: http://{}", addr);
        println!("🛡️  REST API Control Endpoint:        http://{}/status", addr);
        println!("================================================================================");
        info!("🛡️ [KILLSWITCH-SERVER] Local Axum HTTP API & WebUI listening on http://{}", addr);

        let web_url = format!("http://{}", addr);
        open_browser_cross_platform(&web_url);

        // Spawn continuous Live OS-Query & Autonomous Agent Breakout Sentinel loop
        let sentinel_state = Arc::clone(&self.state);
        let sentinel_handle = tokio::spawn(async move {
            let coord = killswitch_telemetry::BreakoutDefenseCoordinator::new();
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));
            loop {
                interval.tick().await;
                let rows = sentinel_state
                    .lineage_engine
                    .rl_traffic
                    .poll_and_learn_live_os_traffic();
                for row in rows {
                    let eval = coord.evaluate_action(
                        &row.process_name,
                        &row.image_path,
                        &row.command_line,
                    );
                    if !eval.is_clean {
                        let _ = sentinel_state
                            .arm_registry
                            .sever_and_regenerate_arm(2, &eval.summary)
                            .await;
                        if *sentinel_state.active_mode.read().await == OrchestratorMode::Autonomous
                            && !sentinel_state.containment_manager.get_status().isolated
                        {
                            let _ = sentinel_state
                                .containment_manager
                                .engage_isolation(
                                    "live_os_ai_breakout_sentinel",
                                    &eval.summary,
                                    killswitch_types::ContainmentLevel::HermeticIsolation,
                                    None,
                                )
                                .await;
                            *sentinel_state.last_trigger_cause.write().await = Some((
                                eval.frontier_framework_classification.clone(),
                                format!("PID {} ({})", row.pid, row.process_name),
                                eval.summary.clone(),
                            ));
                        }
                    }
                }
            }
        });

        let app = build_router(Arc::clone(&self.state));

        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal)
            .await
            .map_err(|e| ServerError::Internal(format!("Server error: {}", e)))?;

        sentinel_handle.abort();

        let _ = std::fs::remove_file("active_port.txt");
        let _ = std::fs::remove_file(std::env::temp_dir().join("killswitch_active_port.txt"));
        info!("🛡️ [KILLSWITCH-SERVER] Server stopped cleanly.");
        Ok(())
    }
}

/// Convenience runner function used by Unified Loader.
pub async fn run_server(config: ServerConfig, mut state: ServerState) -> Result<(), ServerError> {
    state.config = config;
    let server = KillSwitchServer::new(Arc::new(state));
    server.run_with_shutdown(async {
        // Wait for shutdown or let caller manage
        tokio::signal::ctrl_c().await.ok();
    }).await
}

/// Automatically opens the WebUI Dashboard URL in the default system browser
/// across Windows (`explorer.exe`), macOS (`open`), and Linux (`xdg-open` / `gio`).
pub fn open_browser_cross_platform(url: &str) {
    if std::env::var("KILLSWITCH_NO_BROWSER").is_ok() {
        return;
    }

    let target_url = url.to_string();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(250));

        #[cfg(target_os = "windows")]
        {
            let _ = std::process::Command::new("explorer.exe")
                .arg(&target_url)
                .spawn();
        }

        #[cfg(target_os = "macos")]
        {
            let _ = std::process::Command::new("open")
                .arg(&target_url)
                .spawn();
        }

        #[cfg(target_os = "linux")]
        {
            if std::process::Command::new("xdg-open")
                .arg(&target_url)
                .spawn()
                .is_err()
            {
                let _ = std::process::Command::new("gio")
                    .args(["open", &target_url])
                    .spawn();
            }
        }
    });
}
