//! # Server Lifecycle, Configuration & Loopback Binding (Port 3030)
//!
//! Enforces loopback and control port 3030 preservation during full network containment.

use base64::Engine;
use dashmap::DashMap;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::Digest;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
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
use crate::journal::QuarantineJournal;
use crate::orchestrator_bridge::{InMemoryOrchestratorBridge, OrchestratorBridge};
use crate::routes::build_router;

/// Thread-safe TTL-bounded anti-replay cache for single-use CAGE directive nonces.
#[derive(Clone)]
pub struct NonceReplayCache {
    entries: Arc<DashMap<String, Instant>>,
    ttl: Duration,
}

impl NonceReplayCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            ttl,
        }
    }

    pub fn check_and_record(&self, nonce: &str) -> Result<(), String> {
        let now = Instant::now();
        if self.entries.len() > 2000 {
            self.purge_expired();
        }

        if let Some(entry) = self.entries.get(nonce) {
            if now.duration_since(*entry) < self.ttl {
                return Err(format!("Nonce '{}' was already consumed within TTL", nonce));
            }
        }

        self.entries.insert(nonce.to_string(), now);
        Ok(())
    }

    pub fn purge_expired(&self) {
        let now = Instant::now();
        self.entries
            .retain(|_, &mut inserted_at| now.duration_since(inserted_at) < self.ttl);
    }
}

/// Out-of-band CAGE verification key manifest resolver.
#[derive(Clone)]
pub struct CageKeyManifestResolver {
    keys: Arc<DashMap<String, VerifyingKey>>,
}

impl CageKeyManifestResolver {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(DashMap::new()),
        }
    }

    pub fn register_key(&self, kid: &str, key: VerifyingKey) {
        self.keys.insert(kid.to_string(), key);
    }

    pub fn resolve_key(&self, kid: &str) -> Option<VerifyingKey> {
        self.keys.get(kid).map(|k| *k)
    }

    pub fn load_jwks_json(&self, json_str: &str) -> Result<usize, String> {
        let val: serde_json::Value =
            serde_json::from_str(json_str).map_err(|e| format!("Invalid JWKS JSON: {}", e))?;
        let keys_arr = val
            .get("keys")
            .and_then(|k| k.as_array())
            .ok_or_else(|| "Missing 'keys' array in JWKS".to_string())?;

        let mut count = 0;
        for key_obj in keys_arr {
            let kty = key_obj.get("kty").and_then(|v| v.as_str());
            let crv = key_obj.get("crv").and_then(|v| v.as_str());
            let kid = key_obj.get("kid").and_then(|v| v.as_str());
            let x = key_obj.get("x").and_then(|v| v.as_str());

            if kty == Some("OKP") && crv == Some("Ed25519") {
                if let (Some(kid_str), Some(x_str)) = (kid, x) {
                    if let Ok(raw_bytes) =
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(x_str)
                    {
                        if raw_bytes.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&raw_bytes);
                            if let Ok(vk) = VerifyingKey::from_bytes(&arr) {
                                self.register_key(kid_str, vk);
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
        Ok(count)
    }
}

impl Default for CageKeyManifestResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of the latest background OS kernel vulnerability scan.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KernelScanSummary {
    pub scanned_at: chrono::DateTime<chrono::Utc>,
    pub host_kernel: killswitch_kernel_patcher::HostKernelInfo,
    pub vulnerability_count: usize,
    pub cisa_kev_count: usize,
    pub vulnerabilities: Vec<killswitch_kernel_patcher::KernelVulnerability>,
}

/// Configuration for local Axum HTTP control server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub max_body_bytes: usize,
    pub request_timeout_secs: u64,
    pub open_browser: bool,
    pub kernel_scan_interval_secs: u64,
    pub enable_kernel_scan: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3030,
            max_body_bytes: 2 * 1024 * 1024, // 2 MB
            request_timeout_secs: 30,
            open_browser: false,
            kernel_scan_interval_secs: 3600,
            enable_kernel_scan: true,
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
    pub active_bound_port: Arc<std::sync::atomic::AtomicU16>,
    pub fprime_supervisor: Arc<killswitch_core::fprime::FPrimeSupervisor>,
    pub config: ServerConfig,
    pub latest_kernel_scan: Arc<RwLock<Option<KernelScanSummary>>>,

    // --- CAGE Substrate Integration State ---
    pub signing_key: Arc<SigningKey>,
    pub ed25519_kid: String,
    pub jwks_cache: Arc<serde_json::Value>,
    pub cage_key_manifest: Arc<CageKeyManifestResolver>,
    pub replay_cache: Arc<NonceReplayCache>,
    pub journal: Arc<QuarantineJournal>,
    pub control_token: Arc<String>,
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
        // 1. CSPRNG 32-byte seed for ArmRingRegistry
        let octopus_master_seed = {
            let mut s = [0u8; 32];
            use rand::RngCore;
            rand::rngs::OsRng.fill_bytes(&mut s);
            s
        };

        // 2. Generate asymmetric Ed25519 keypair
        let signing_key = Arc::new(SigningKey::generate(&mut rand::rngs::OsRng));
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        // 3. Derive 64-hex SHA-256 kid
        let ed25519_kid = hex::encode(sha2::Sha256::digest(pub_bytes));

        // 4. Encode x base64url unpadded
        let x_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_bytes);

        // 5. Pre-render RFC 8037 JWKS
        let jwks_cache = Arc::new(serde_json::json!({
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "kid": ed25519_kid,
                    "x": x_b64,
                    "use": "sig",
                    "alg": "EdDSA"
                }
            ]
        }));

        // 6. Initialize manifest & replay cache (TTL 300s)
        let cage_key_manifest = Arc::new(CageKeyManifestResolver::new());
        if let Ok(manifest_path) = std::env::var("CAGE_TRUSTED_JWKS_PATH") {
            if let Ok(content) = std::fs::read_to_string(&manifest_path) {
                let _ = cage_key_manifest.load_jwks_json(&content);
            }
        }
        if let Ok(manifest_json) = std::env::var("CAGE_TRUSTED_JWKS_JSON") {
            let _ = cage_key_manifest.load_jwks_json(&manifest_json);
        }
        let replay_cache = Arc::new(NonceReplayCache::new(Duration::from_secs(300)));

        // 7. Initialize QuarantineJournal
        let state_dir = std::env::var("KILLSWITCH_STATE_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("killswitch_state"));
        let journal = Arc::new(QuarantineJournal::new(
            state_dir,
            Arc::clone(&signing_key),
            ed25519_kid.clone(),
        ));

        // 8. Control Plane Token (R4 — CSPRNG / DPAPI-ACL host secret only, never static phrases)
        let control_token = std::env::var("KILLSWITCH_CONTROL_TOKEN")
            .or_else(|_| std::env::var("KILLSWITCH_MASTER_TOKEN"))
            .ok()
            .and_then(|tok| {
                let trimmed = tok.trim().to_string();
                if trimmed.len() >= 32
                    && !killswitch_core::auth::is_forbidden_static_token(&trimmed)
                {
                    Some(trimmed)
                } else {
                    tracing::warn!(
                        "Ignoring weak or forbidden static control token override; provisioning CSPRNG secret"
                    );
                    None
                }
            })
            .unwrap_or_else(|| {
                if std::env::var_os("CARGO").is_some()
                    || std::env::var_os("RUST_TEST_THREADS").is_some()
                {
                    killswitch_core::auth::generate_csprng_token_hex().unwrap_or_else(|_| {
                        let mut bytes = [0u8; 32];
                        use rand::RngCore;
                        rand::rngs::OsRng.fill_bytes(&mut bytes);
                        format!("ks-op-{}", hex::encode(bytes))
                    })
                } else {
                    killswitch_core::auth::load_or_provision_host_control_secret().unwrap_or_else(
                        |_| {
                            let mut bytes = [0u8; 32];
                            use rand::RngCore;
                            rand::rngs::OsRng.fill_bytes(&mut bytes);
                            format!("ks-op-{}", hex::encode(bytes))
                        },
                    )
                }
            });
        let control_token = Arc::new(control_token);

        Self {
            containment_manager,
            adjudicator,
            lineage_engine,
            arm_registry: Arc::new(ArmRingRegistry::new(&octopus_master_seed)),
            event_correlator: Arc::new(EventCorrelator::default()),
            phaselock_manager: Arc::new(PhaseLockManager::default()),
            service_manager,
            orchestrator_bridge,
            start_time: Instant::now(),
            active_mode: Arc::new(RwLock::new(OrchestratorMode::Autonomous)),
            last_trigger_cause: Arc::new(RwLock::new(None)),
            peers_enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            active_bound_port: Arc::new(std::sync::atomic::AtomicU16::new(3030)),
            fprime_supervisor: Arc::new(killswitch_core::fprime::FPrimeSupervisor::new()),
            config: ServerConfig::default(),
            latest_kernel_scan: Arc::new(RwLock::new(None)),

            signing_key,
            ed25519_kid,
            jwks_cache,
            cage_key_manifest,
            replay_cache,
            journal,
            control_token,
        }
    }

    pub fn with_defaults(containment_manager: Arc<HostContainmentManager>) -> Self {
        let adjudicator = Arc::new(ZeroFalsePositiveAdjudicator::new());
        let lineage_engine = Arc::new(EndpointLineageEngine::new_in_memory());
        let orchestrator_bridge = Arc::new(InMemoryOrchestratorBridge::default());
        let service_manager = default_service_manager();
        Self::new(
            containment_manager,
            adjudicator,
            lineage_engine,
            orchestrator_bridge,
            service_manager,
        )
    }

    pub fn is_valid_control_token(&self, candidate: &str) -> bool {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            return false;
        }

        if crate::auth::constant_time_token_match(trimmed, &self.control_token) {
            return true;
        }

        // No hardcoded fallback master token permitted. Only accept validated cryptographic tokens
        // from ServerState (CSPRNG runtime secret or operator env/stored token).

        if let Ok(env_tok) = std::env::var("KILLSWITCH_CONTROL_TOKEN") {
            if crate::auth::constant_time_token_match(trimmed, env_tok.trim()) {
                return true;
            }
        }
        if let Ok(env_tok) = std::env::var("KILLSWITCH_MASTER_TOKEN") {
            if crate::auth::constant_time_token_match(trimmed, env_tok.trim()) {
                return true;
            }
        }

        let creds = killswitch_types::status::OperatorCredentials {
            operator_id: "control_plane".to_string(),
            auth_token: Some(trimmed.to_string()),
            password: Some(trimmed.to_string()),
            caller_pid: None,
            confirmation_phrase: Some(trimmed.to_string()),
        };
        self.containment_manager
            .authenticator()
            .authenticate(&creds)
            .is_success()
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

            // Check OS kernel TCP LISTEN table + active probe so hung SO_REUSEADDR listeners
            // (e.g., deadlocked daemons on 127.0.0.1:3030) never hijack WebUI browser connections.
            if port != 0 {
                if killswitch_core::wfp::is_local_tcp_port_listening(port) {
                    tracing::warn!(
                        "⚠️ [KILLSWITCH-SERVER] Port {} already has an OS LISTEN socket in GetTcpTable; trying next port...",
                        port
                    );
                    continue;
                }

                let probe_busy = tokio::time::timeout(
                    std::time::Duration::from_millis(120),
                    tokio::net::TcpStream::connect(addr),
                )
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);

                if probe_busy {
                    tracing::warn!(
                        "⚠️ [KILLSWITCH-SERVER] Port {} is already occupied by an active or hung listener; trying next port...",
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
                    return Err(ServerError::Internal(format!(
                        "Failed to bind to {}: {}",
                        addr, e
                    )));
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

        self.state
            .active_bound_port
            .store(bound_port, std::sync::atomic::Ordering::SeqCst);

        // Persist the active port so CLI subcommands and elevated helpers can auto-discover it
        let port_str = bound_port.to_string();
        let _ = std::fs::write("active_port.txt", &port_str);
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let exe_port_file = dir.join("active_port.txt");
                if !exe_port_file.is_symlink() {
                    let _ = std::fs::write(&exe_port_file, &port_str);
                }
            }
        }

        println!(
            "================================================================================"
        );
        println!("🌐  KILLSWITCH WEBUI DASHBOARD READY: http://{}", addr);
        println!(
            "🛡️  REST API Control Endpoint:        http://{}/status",
            addr
        );
        println!(
            "================================================================================"
        );
        info!(
            "🛡️ [KILLSWITCH-SERVER] Local Axum HTTP API & WebUI listening on http://{}",
            addr
        );

        let web_url = format!("http://{}", addr);
        if self.state.config.open_browser {
            open_browser_cross_platform(&web_url);
        }

        // Spawn continuous Live OS-Query & Adjudicated Agent Breakout Sentinel loop
        let sentinel_state = Arc::clone(&self.state);
        let sentinel_handle = tokio::spawn(async move {
            let self_pid = std::process::id();
            let mut evaluated_signatures: std::collections::HashSet<(u32, String)> =
                std::collections::HashSet::new();
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(5000));
            loop {
                interval.tick().await;
                let rl_traffic = Arc::clone(&sentinel_state.lineage_engine.rl_traffic);
                let Ok(rows) = tokio::task::spawn_blocking(move || {
                    rl_traffic.poll_and_learn_live_os_traffic()
                })
                .await
                else {
                    continue;
                };
                let mut active_pids = std::collections::HashSet::new();
                for row in &rows {
                    active_pids.insert(row.pid);
                }
                evaluated_signatures.retain(|(pid, _)| active_pids.contains(pid));

                for row in rows {
                    if row.pid == self_pid || row.command_line.trim().is_empty() {
                        continue;
                    }
                    let sig = (row.pid, row.command_line.clone());
                    if !evaluated_signatures.insert(sig) {
                        continue;
                    }

                    // Dynamic Binary Metadata Probing & Parent-Child Token Delta Observation
                    let mut is_priv_binary = false;
                    if !row.image_path.is_empty() {
                        let path = std::path::Path::new(&row.image_path);
                        if let Ok(meta) = killswitch_adjudication::inspect_binary_metadata(path) {
                            if meta.is_privileged_target() {
                                is_priv_binary = true;
                            }
                        }
                    }

                    let token_deltas = if row.parent_pid > 0 {
                        killswitch_adjudication::observe_parent_child_token_delta(
                            row.parent_pid,
                            row.pid,
                        )
                    } else {
                        Vec::new()
                    };
                    let has_priv_escalation =
                        token_deltas.iter().any(|d| d.is_privilege_escalation());

                    // Fresh per-candidate breakout evaluation so OS process enumeration does not self-poison rate limits
                    let coord = killswitch_telemetry::BreakoutDefenseCoordinator::new();
                    let eval = coord.evaluate_action(
                        &row.process_name,
                        &row.image_path,
                        &row.command_line,
                    );
                    if !eval.technical.is_clean || !eval.operational.is_clean || !eval.data.is_clean
                    {
                        let base_score = eval.breakout_risk_score as f32;
                        let elevated_score = if has_priv_escalation || is_priv_binary {
                            f32::max(base_score, 0.95)
                        } else {
                            base_score
                        };
                        let summary = if has_priv_escalation {
                            format!("{} [Token Escalation Detected]", eval.summary)
                        } else if is_priv_binary {
                            format!("{} [Privileged Binary Metadata Probed]", eval.summary)
                        } else {
                            eval.summary.clone()
                        };

                        // Mandatory Decision Model & 5-Layer Zero-False-Positive Adjudication Governance
                        let mut candidate = killswitch_types::adjudication::ThreatCandidate::new(
                            Some(row.pid),
                            &row.process_name,
                            "live_os_ai_breakout_sentinel",
                            &summary,
                            elevated_score,
                            killswitch_types::adjudication::EvidenceClass::Behavior,
                        );
                        if !row.image_path.is_empty() {
                            candidate.binary_path = Some(row.image_path.clone());
                        }
                        candidate.command_line = Some(row.command_line.clone());

                        let adj_ctx = killswitch_adjudication::voters::AdjudicationContext {
                            process_ancestry: killswitch_adjudication::get_process_ancestry_chain(
                                row.pid,
                            ),
                            ..Default::default()
                        };
                        let verdict = sentinel_state
                            .adjudicator
                            .adjudicate_threat_candidate(&candidate, Some(&adj_ctx))
                            .await;
                        if !verdict.is_confirmed() {
                            continue;
                        }

                        let _ = sentinel_state
                            .arm_registry
                            .sever_and_regenerate_arm(2, &eval.summary)
                            .await;
                        killswitch_core::TrackedAgentTreeRegistry::global()
                            .register_agent_root(row.pid, &row.process_name);
                        for (anc_pid, anc_name) in &adj_ctx.process_ancestry {
                            if killswitch_core::is_developer_or_agent_runtime(anc_name)
                                && !killswitch_core::is_immutable_os_kernel_pid(*anc_pid, anc_name)
                            {
                                killswitch_core::TrackedAgentTreeRegistry::global()
                                    .register_agent_root(*anc_pid, anc_name);
                            }
                        }
                        if *sentinel_state.active_mode.read().await == OrchestratorMode::Autonomous
                            && !sentinel_state.containment_manager.get_status().isolated
                        {
                            let _ = sentinel_state
                                .containment_manager
                                .engage_isolation_for_target(
                                    "live_os_ai_breakout_sentinel",
                                    &eval.summary,
                                    killswitch_types::ContainmentLevel::HermeticIsolation,
                                    Some(std::process::id()),
                                    Some(row.pid),
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

        // Spawn periodic OS Kernel Vulnerability & CISA KEV Scanner loop
        let patcher_state = Arc::clone(&self.state);
        let patcher_handle = tokio::spawn(async move {
            run_periodic_kernel_scanner(patcher_state).await;
        });

        // Re-enforce unexpired leases from journal fail-closed on startup
        let _ = self
            .state
            .journal
            .recover_and_re_enforce(&self.state.containment_manager)
            .await;

        let app = build_router(Arc::clone(&self.state));

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal)
        .await
        .map_err(|e| ServerError::Internal(format!("Server error: {}", e)))?;

        sentinel_handle.abort();
        patcher_handle.abort();

        let _ = std::fs::remove_file("active_port.txt");
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let exe_port_file = dir.join("active_port.txt");
                if !exe_port_file.is_symlink() {
                    let _ = std::fs::remove_file(&exe_port_file);
                }
            }
        }
        info!("🛡️ [KILLSWITCH-SERVER] Server stopped cleanly.");
        Ok(())
    }
}

/// Convenience runner function used by Unified Loader.
pub async fn run_server(config: ServerConfig, mut state: ServerState) -> Result<(), ServerError> {
    state.config = config;
    let server = KillSwitchServer::new(Arc::new(state));
    server
        .run_with_shutdown(async {
            // Wait for shutdown or let caller manage
            tokio::signal::ctrl_c().await.ok();
        })
        .await
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
            let _ = std::process::Command::new("open").arg(&target_url).spawn();
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

/// Executes a single OS kernel vulnerability scan cycle against NVD API 2.0 / CISA KEV.
/// Returns the number of vulnerabilities detected, or PatcherError on failure.
pub async fn run_periodic_kernel_scan_cycle(
    state: &ServerState,
) -> Result<usize, killswitch_kernel_patcher::PatcherError> {
    // 1. Detect host platform and kernel release version (offloaded to avoid blocking worker thread)
    let host_kernel =
        tokio::task::spawn_blocking(killswitch_kernel_patcher::HostKernelInfo::detect_host_kernel)
            .await
            .map_err(|e| {
                killswitch_kernel_patcher::PatcherError::DetectionFailed(e.to_string())
            })??;

    tracing::info!(
        "🛡️ [KERNEL-SCANNER] Detected host OS: {} | Kernel: {} | CPE: {}",
        host_kernel.os_family,
        host_kernel.kernel_release,
        host_kernel.cpe23
    );

    // 2. Resolve NVD_API_KEY strictly from runtime environment variable
    // Invariant: Zero leakage into CLI args, process tables, or persistent configs
    let api_key = std::env::var("NVD_API_KEY").ok().and_then(|k| {
        let trimmed = k.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    });

    if api_key.is_some() {
        tracing::info!(
            "🔑 [KERNEL-SCANNER] Using authenticated NVD API 2.0 key for elevated rate limits"
        );
    } else {
        tracing::debug!(
            "ℹ️ [KERNEL-SCANNER] No NVD_API_KEY detected in environment; using public rate limits"
        );
    }

    // 3. Configure ScanOptions
    let options = killswitch_kernel_patcher::ScanOptions {
        cpe: Some(host_kernel.cpe23.clone()),
        min_cvss_score: None,
        kev_only: false,
        api_key,
        timeout_secs: 30,
    };

    // 4. Execute scan via KernelPatcher
    let patcher = killswitch_kernel_patcher::KernelPatcher::new();
    let findings = patcher.scan_kernel_vulnerabilities(&options).await?;

    let kev_count = findings.iter().filter(|v| v.is_cisa_kev).count();
    let total_count = findings.len();

    if total_count == 0 {
        tracing::info!(
            "🛡️ [KERNEL-SCANNER] Kernel vulnerability scan complete: 0 vulnerabilities found for host CPE {}",
            host_kernel.cpe23
        );
    } else {
        tracing::warn!(
            "⚠️ [KERNEL-SCANNER] Kernel vulnerability scan complete: {} vulnerabilities found ({} CISA KEV) for host CPE {}",
            total_count,
            kev_count,
            host_kernel.cpe23
        );

        for finding in findings.iter().take(5) {
            if finding.is_cisa_kev {
                tracing::warn!(
                    "🚨 [KERNEL-SCANNER] CISA KEV: {} (CVSS {:?}): {}",
                    finding.cve_id,
                    finding.cvss_v31_score,
                    finding.description
                );
            } else {
                tracing::info!(
                    "ℹ️ [KERNEL-SCANNER] Vulnerability: {} (CVSS {:?}): {}",
                    finding.cve_id,
                    finding.cvss_v31_score,
                    finding.description
                );
            }
        }
    }

    // 5. Update cached scan summary in ServerState
    let summary = KernelScanSummary {
        scanned_at: chrono::Utc::now(),
        host_kernel,
        vulnerability_count: total_count,
        cisa_kev_count: kev_count,
        vulnerabilities: findings,
    };
    *state.latest_kernel_scan.write().await = Some(summary);

    Ok(total_count)
}

/// Background loop executing periodic kernel vulnerability scans.
pub async fn run_periodic_kernel_scanner(state: Arc<ServerState>) {
    let interval_secs = std::env::var("KILLSWITCH_KERNEL_SCAN_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(state.config.kernel_scan_interval_secs)
        .max(10); // Minimum clamp 10s

    let enabled =
        std::env::var("KILLSWITCH_DISABLE_KERNEL_SCAN").is_err() && state.config.enable_kernel_scan;

    if !enabled {
        tracing::info!(
            "ℹ️ [KERNEL-SCANNER] Periodic kernel vulnerability scanning disabled by config/env"
        );
        return;
    }

    tracing::info!(
        "🛡️ [KERNEL-SCANNER] Starting periodic kernel vulnerability scanner (interval: {}s)",
        interval_secs
    );

    // Initial delay before first scan so server startup completes swiftly without blocking
    let initial_delay_secs = std::env::var("KILLSWITCH_KERNEL_SCAN_INITIAL_DELAY_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5);

    tokio::time::sleep(tokio::time::Duration::from_secs(initial_delay_secs)).await;

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tracing::debug!(
            "🛡️ [KERNEL-SCANNER] Initiating periodic kernel vulnerability scan cycle..."
        );
        match run_periodic_kernel_scan_cycle(&state).await {
            Ok(count) => {
                tracing::debug!(
                    "🛡️ [KERNEL-SCANNER] Scan cycle finished: {} findings",
                    count
                );
            }
            Err(killswitch_kernel_patcher::PatcherError::RateLimited) => {
                tracing::warn!(
                    "⚠️ [KERNEL-SCANNER] NVD API rate-limit reached; skipping until next scheduled cycle"
                );
            }
            Err(e) => {
                tracing::warn!(
                    "⚠️ [KERNEL-SCANNER] Periodic kernel vulnerability scan cycle encountered error: {}",
                    e
                );
            }
        }

        interval.tick().await;
    }
}
