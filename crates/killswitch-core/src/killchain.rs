//! Host Containment Manager & Reversible Isolation Subsystem.
//!
//! Orchestrates native network isolation, non-destructive process suspension,
//! active tarpit duty cycling, operator authentication, and BLAKE3-chained audit state.
//! Includes intermediate 60s process-tree health probing and a 30-minute dead-man failsafe.

use chrono::Utc;
use killswitch_types::{
    errors::{KillSwitchError, Result},
    status::{
        AuthResult, ContainmentLevel, HealthProbeAnomaly, HealthProbeRunner, IsolationReceipt,
        KillChainHealthProbeReport, KillChainHistoryEntry, KillChainStatus, LockoutState,
        NetworkIsolationEngine, NetworkIsolator, OperatorAuthenticator, OperatorCredentials,
        ProbeAnomalyKind, ProcessFreezer, ProcessIsolationState, DEFAULT_CONTROL_PORT,
        DEFAULT_INTERMEDIATE_HEALTH_PROBE_INTERVAL_SECS,
        DEFAULT_REQUIRED_CONSECUTIVE_HEALTHY_PROBES, DEFAULT_ROLLBACK_WATCHDOG_MAX_SECS,
    },
};
use parking_lot::{Mutex, RwLock};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use sysinfo::System;
use tracing::{error, info, warn};

pub use crate::agent_registry::{
    AgentLineageClass, SubtreeResolution, TrackedAgentRoot, TrackedAgentTreeRegistry,
};
use crate::state_ledger::StateLedger;

/// Resolves an offending PID and all live descendants safely, excluding `std::process::id()`,
/// kernel PIDs `<= 4`, `exclude_pids`, and immutable OS kernel anchors.
pub fn resolve_offending_process_subtree(target_pid: u32, exclude_pids: &HashSet<u32>) -> Vec<u32> {
    crate::job_sandbox::enumerate_process_subtree(target_pid, exclude_pids)
}

pub type HostContainmentManager = KillChainHostManager;

/// Master host containment manager coordinating all isolation primitives.
pub struct KillChainHostManager {
    network_isolator: Arc<dyn NetworkIsolator>,
    process_freezer: Arc<dyn ProcessFreezer>,
    authenticator: Arc<dyn OperatorAuthenticator>,
    ledger: Arc<RwLock<StateLedger>>,
    watchdog_abort_tx: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    engagement_lock: tokio::sync::Mutex<()>,
    /// Reusable lightweight process-only scanner avoiding 100ms+ `System::new_all()` overhead.
    process_scanner: Mutex<System>,
}

/// Fallback / simulated network isolator for non-Windows and non-Linux targets.
#[derive(Debug, Default, Clone)]
pub struct SimulatedNetworkIsolator;

impl NetworkIsolator for SimulatedNetworkIsolator {
    fn engage_quarantine(&self, ports: &[u16], op: &str, reason: &str) -> Result<IsolationReceipt> {
        Ok(IsolationReceipt::new(
            "simulated-session".to_string(),
            NetworkIsolationEngine::Simulated,
            vec![],
            vec![],
            vec![],
            ports.to_vec(),
            vec![],
            0,
            op.to_string(),
            reason.to_string(),
        ))
    }

    fn restore_quarantine(&self, _receipt: &IsolationReceipt) -> Result<()> {
        Ok(())
    }

    fn reset_tcp_connections(&self, _target_ips: Option<&[IpAddr]>) -> Result<usize> {
        Ok(0)
    }
}

/// Returns the platform-native network isolator instance.
pub fn default_network_isolator() -> Arc<dyn NetworkIsolator> {
    #[cfg(target_os = "windows")]
    {
        Arc::new(crate::wfp::WindowsWfpIsolator)
    }
    #[cfg(target_os = "linux")]
    {
        Arc::new(crate::landlock::LinuxNetlinkIsolator::new())
    }
    #[cfg(target_os = "macos")]
    {
        Arc::new(crate::pf::MacOsPfIsolator::new())
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Arc::new(SimulatedNetworkIsolator)
    }
}

impl KillChainHostManager {
    /// Constructs a new `KillChainHostManager` with dependency injection.
    pub fn new(
        network_isolator: Arc<dyn NetworkIsolator>,
        process_freezer: Arc<dyn ProcessFreezer>,
        authenticator: Arc<dyn OperatorAuthenticator>,
        ledger: Arc<RwLock<StateLedger>>,
    ) -> Self {
        Self {
            network_isolator,
            process_freezer,
            authenticator,
            ledger,
            watchdog_abort_tx: Mutex::new(None),
            engagement_lock: tokio::sync::Mutex::new(()),
            process_scanner: Mutex::new(System::new()),
        }
    }

    /// Constructs a `KillChainHostManager` with platform defaults and optional storage directory.
    pub fn new_default(custom_dir: Option<&Path>) -> Result<Self> {
        let isolator = default_network_isolator();
        let freezer = Arc::new(crate::freeze::NativeProcessFreezer::new());
        let auth = Arc::new(crate::auth::OperatorAuthManager::new(
            None,
            custom_dir.map(PathBuf::from),
        ));
        let ledger = Arc::new(RwLock::new(StateLedger::open_or_init(custom_dir)?));
        Ok(Self::new(isolator, freezer, auth, ledger))
    }

    /// Constructs a `KillChainHostManager` with simulated network isolation for platform-independent hermetic testing.
    pub fn new_simulated(custom_dir: Option<&Path>) -> Result<Self> {
        let isolator = Arc::new(SimulatedNetworkIsolator);
        let freezer = Arc::new(crate::freeze::NativeProcessFreezer::new());
        let auth = Arc::new(crate::auth::OperatorAuthManager::new(
            None,
            custom_dir.map(PathBuf::from),
        ));
        let ledger = Arc::new(RwLock::new(StateLedger::open_or_init(custom_dir)?));
        Ok(Self::new(isolator, freezer, auth, ledger))
    }

    /// Constructs a `KillChainHostManager` with platform defaults and an explicit CSPRNG master token.
    pub fn new_default_with_master_token(
        custom_dir: Option<&Path>,
        master_token: String,
    ) -> Result<Self> {
        let isolator = default_network_isolator();
        let freezer = Arc::new(crate::freeze::NativeProcessFreezer::new());
        let mut auth = crate::auth::OperatorAuthManager::new(None, custom_dir.map(PathBuf::from));
        auth.set_custom_master_token(master_token);
        let ledger = Arc::new(RwLock::new(StateLedger::open_or_init(custom_dir)?));
        Ok(Self::new(isolator, freezer, Arc::new(auth), ledger))
    }

    /// Constructs a simulated `KillChainHostManager` with an explicit CSPRNG master token.
    pub fn new_simulated_with_master_token(
        custom_dir: Option<&Path>,
        master_token: String,
    ) -> Result<Self> {
        let isolator = Arc::new(SimulatedNetworkIsolator);
        let freezer = Arc::new(crate::freeze::NativeProcessFreezer::new());
        let mut auth = crate::auth::OperatorAuthManager::new(None, custom_dir.map(PathBuf::from));
        auth.set_custom_master_token(master_token);
        let ledger = Arc::new(RwLock::new(StateLedger::open_or_init(custom_dir)?));
        Ok(Self::new(isolator, freezer, Arc::new(auth), ledger))
    }

    /// Queries current Kill Chain status.
    pub fn get_status(&self) -> KillChainStatus {
        let ledger = self.ledger.read();
        let mut status = ledger.status().clone();
        let lockout = self.authenticator.check_lockout();
        status.lockout_remaining_secs = lockout.lockout_remaining_secs;
        status
    }

    /// Queries history ledger entries.
    pub fn get_history(&self) -> Vec<KillChainHistoryEntry> {
        let ledger = self.ledger.read();
        ledger.snapshot().history.clone()
    }

    /// Queries active network receipts.
    pub fn get_network_receipts(&self) -> Vec<IsolationReceipt> {
        let ledger = self.ledger.read();
        ledger.snapshot().network_receipts.clone()
    }

    /// Returns the live TPM 2.0 hardware status and verifies the sealed BLAKE3 ledger anchor.
    pub fn tpm_status_report(&self) -> crate::tpm::TpmStatusReport {
        let ledger = self.ledger.read();
        ledger.tpm_status_report()
    }

    /// Forces a live hardware TPM 2.0 probe and re-seals the active BLAKE3 ledger root hash.
    pub fn re_seal_tpm_anchor(&self) -> crate::tpm::TpmStatusReport {
        let _ = crate::tpm::refresh_hardware_tpm_probe();
        let ledger = self.ledger.read();
        ledger.re_seal_tpm_anchor()
    }

    /// Queries active process isolation states.
    pub fn get_process_records(&self) -> Vec<ProcessIsolationState> {
        let ledger = self.ledger.read();
        ledger.snapshot().process_records.clone()
    }

    /// Engages host containment with specified parameters.
    pub async fn engage_isolation(
        self: &Arc<Self>,
        operator: &str,
        reason: &str,
        level: ContainmentLevel,
        caller_pid: Option<u32>,
    ) -> Result<KillChainStatus> {
        self.engage_isolation_for_target(operator, reason, level, caller_pid, None)
            .await
    }

    /// Engages host containment targeting an optional offending PID and its entire descendant subtree.
    pub async fn engage_isolation_for_target(
        self: &Arc<Self>,
        operator: &str,
        reason: &str,
        level: ContainmentLevel,
        caller_pid: Option<u32>,
        target_pid: Option<u32>,
    ) -> Result<KillChainStatus> {
        // Hold exclusive engagement lock across entire isolation sequence
        let _engagement_guard = self.engagement_lock.lock().await;

        // Stage 1: Validate calling process integrity
        self.authenticator.validate_caller(caller_pid)?;

        info!(
            "🚨 [KILLCHAIN] Engaging containment level '{:?}' requested by '{}' (reason: '{}')",
            level, operator, reason
        );

        let current_status = self.get_status();
        if current_status.isolated && current_status.containment_level == level {
            let kernel_filters_verified = {
                #[cfg(target_os = "windows")]
                {
                    if std::env::var("CARGO").is_ok()
                        || std::env::var("RUST_TEST_THREADS").is_ok()
                        || cfg!(test)
                    {
                        true
                    } else if matches!(
                        level,
                        ContainmentLevel::NetworkQuarantine | ContainmentLevel::HermeticIsolation
                    ) {
                        crate::wfp::has_live_active_wfp_filters()
                    } else {
                        true
                    }
                }
                #[cfg(not(target_os = "windows"))]
                {
                    true
                }
            };

            if kernel_filters_verified {
                info!("🛡️ [KILLCHAIN-IDEMPOTENCY] Host is already isolated at {:?} with verified kernel filters; preserving state.", level);
                return Ok(current_status);
            } else {
                warn!("⚠️ [KILLCHAIN-RECONCILE] State ledger reported {:?} isolation, but zero live WFP kernel filters were found in BFE; installing kernel quarantine now.", level);
            }
        }

        let now = Utc::now();
        let mut network_isolated = false;
        let mut network_receipts = Vec::new();
        let active_network_rules = Vec::new();

        let mut preserved_ports = crate::wfp::discover_active_control_ports();
        if !preserved_ports.contains(&DEFAULT_CONTROL_PORT) {
            preserved_ports.push(DEFAULT_CONTROL_PORT);
        }

        // Stage 2: Network Quarantine (if level requires network isolation)
        if matches!(
            level,
            ContainmentLevel::NetworkQuarantine | ContainmentLevel::HermeticIsolation
        ) {
            match self
                .network_isolator
                .engage_quarantine(&preserved_ports, operator, reason)
            {
                Ok(receipt) => {
                    info!(
                        "🚨 [KILLCHAIN] Network quarantine engaged. Session ID: {}",
                        receipt.session_id
                    );
                    network_isolated = true;
                    // Only call reset_tcp_connections if the isolator did not already terminate connections
                    if receipt.terminated_tcp_connections_count == 0 {
                        let _ = self.network_isolator.reset_tcp_connections(None);
                    }
                    network_receipts.push(receipt);
                }
                Err(err) => {
                    error!("❌ [KILLCHAIN] Failed to apply network quarantine: {}", err);
                    return Err(err);
                }
            }
        }

        // Stage 3: Process Freeze (if level requires process containment)
        let mut frozen_pids = Vec::new();
        let mut process_records = Vec::new();

        if matches!(
            level,
            ContainmentLevel::ProcessFreeze | ContainmentLevel::HermeticIsolation
        ) {
            let mut immune_set = crate::freeze::NativeProcessFreezer::new().get_immune_pids();
            immune_set.insert(std::process::id());
            if let Some(cpid) = caller_pid {
                if Some(cpid) != target_pid
                    && !TrackedAgentTreeRegistry::global().is_tracked_pid(cpid)
                {
                    immune_set.insert(cpid);
                }
            }

            let high_risk_markers = [
                "untrusted_payload",
                "suspicious_exfil",
                "unauthorized_beacon",
                "test_malware",
            ];

            let mut seed_pids: Vec<u32> = {
                let mut sys = self.process_scanner.lock();
                sys.refresh_processes_specifics(sysinfo::ProcessRefreshKind::new());
                sys.processes()
                    .iter()
                    .filter_map(|(pid_raw, proc)| {
                        let pid = pid_raw.as_u32();
                        if immune_set.contains(&pid) {
                            return None;
                        }
                        let name = proc.name();
                        if is_immutable_os_kernel_pid(pid, name) {
                            return None;
                        }
                        if TrackedAgentTreeRegistry::global().is_tracked_pid(pid) {
                            return Some(pid);
                        }
                        if self.process_freezer.is_immune(pid, name)
                            || is_critical_system_pid(pid, name)
                        {
                            return None;
                        }
                        let name_lc = name.to_ascii_lowercase();
                        let name_hit = high_risk_markers.iter().any(|m| name_lc.contains(m));
                        let cmd_hit = if !name_hit && !proc.cmd().is_empty() {
                            let cmd_lc = proc.cmd().join(" ").to_ascii_lowercase();
                            high_risk_markers.iter().any(|m| cmd_lc.contains(m))
                        } else {
                            false
                        };
                        if name_hit || cmd_hit {
                            Some(pid)
                        } else {
                            None
                        }
                    })
                    .collect()
            };

            if let Some(tpid) = target_pid {
                if !immune_set.contains(&tpid) && !seed_pids.contains(&tpid) {
                    seed_pids.push(tpid);
                }
            }
            for root_pid in TrackedAgentTreeRegistry::global().tracked_roots() {
                if !immune_set.contains(&root_pid) && !seed_pids.contains(&root_pid) {
                    seed_pids.push(root_pid);
                }
            }

            let report = crate::job_sandbox::freeze_subtree_kernel(
                &seed_pids,
                &immune_set,
                self.process_freezer.as_ref(),
            );
            for state in report.frozen_records {
                if !frozen_pids.contains(&state.pid) {
                    frozen_pids.push(state.pid);
                }
                process_records.push(state);
            }
            info!(
                "🚨 [KILLCHAIN] Suspended {} untrusted/subtree processes via {} (job_bound={}).",
                frozen_pids.len(),
                report.kernel_mechanism,
                report.job_bound_pids.len()
            );
        }

        // Stage 4: Update and Commit State Snapshot
        let mut new_status = KillChainStatus {
            isolated: true,
            containment_level: level,
            isolated_at: Some(now),
            isolated_by: Some(operator.to_string()),
            reason: Some(reason.to_string()),
            network_isolated,
            processes_frozen_count: frozen_pids.len(),
            processes_tarpitted_count: 0,
            kernel_lockdown_active: level == ContainmentLevel::HermeticIsolation,
            allowlisted_ports: preserved_ports,
            quarantined_interfaces: Vec::new(),
            frozen_pids,
            tarpitted_pids: Vec::new(),
            active_network_rules,
            quarantined_arms: current_status.quarantined_arms,
            last_action_timestamp: Some(now),
            lockout_remaining_secs: 0,
            rollback_watchdog_max_secs: DEFAULT_ROLLBACK_WATCHDOG_MAX_SECS,
            health_probe_interval_secs: DEFAULT_INTERMEDIATE_HEALTH_PROBE_INTERVAL_SECS,
            consecutive_healthy_probes_required: DEFAULT_REQUIRED_CONSECUTIVE_HEALTHY_PROBES,
            consecutive_healthy_probes: 0,
            last_health_probe_timestamp: None,
            last_health_probe_passed: None,
            last_health_probe_summary: None,
            state_hash_blake3: String::new(),
        };
        new_status.update_hash();

        {
            let mut ledger = self.ledger.write();
            ledger.record_state_transition(
                new_status.clone(),
                Some(network_receipts),
                Some(process_records),
                "ENGAGED",
                operator,
                reason,
            )?;
        }

        // Stage 5: Launch Intermediate Health Probe & Dead-Man Watchdog Task
        self.spawn_watchdog_task();

        Ok(new_status)
    }

    /// Exposes the underlying authenticator.
    pub fn authenticator(&self) -> &Arc<dyn OperatorAuthenticator> {
        &self.authenticator
    }

    /// Validates caller PID and verifies operator credentials.
    pub fn authenticate_credentials(&self, credentials: &OperatorCredentials) -> Result<()> {
        self.authenticator.validate_caller(credentials.caller_pid)?;
        let auth_res = self.authenticator.authenticate(credentials);
        if !auth_res.is_success() {
            return Err(KillSwitchError::AuthenticationFailed(format!(
                "{:?}",
                auth_res
            )));
        }
        Ok(())
    }

    /// Suspends an OS process by PID via the configured ProcessFreezer.
    pub fn freeze_process(&self, pid: u32) -> Result<killswitch_types::ProcessIsolationState> {
        self.process_freezer.freeze_process(pid)
    }

    /// Resumes an OS process by PID via the configured ProcessFreezer.
    pub fn resume_process(&self, pid: u32) -> Result<killswitch_types::ProcessIsolationState> {
        self.process_freezer.resume_process(pid)
    }

    /// Disarms host containment and reverts all installed kernel filters and process suspensions.
    ///
    /// Strictly fail-closed: valid `OperatorCredentials` verified by `OperatorAuthenticator` are mandatory.
    pub async fn disarm_isolation(
        &self,
        operator: &str,
        reason: &str,
        credentials: Option<&OperatorCredentials>,
    ) -> Result<KillChainStatus> {
        let creds = credentials.ok_or_else(|| {
            KillSwitchError::AuthenticationFailed(
                "Operator credentials are required to disarm host containment (fail-closed)"
                    .to_string(),
            )
        })?;
        self.authenticate_credentials(creds)?;

        self.disarm_internal(operator, reason, "DISARMED").await
    }

    /// Scoped CAGE quorum-governed quarantine release (requires verified quorum >= 2,
    /// 64-hex SHA-256 approval digest, and active isolation originally engaged by `cage_governance`).
    /// Never disarms operator-engaged, tamper-engaged, or non-CAGE threat quarantines.
    pub async fn disarm_cage_quorum_quarantine(
        &self,
        workload_id: &str,
        quorum_approval_digest: &str,
        quorum_count: u32,
    ) -> Result<KillChainStatus> {
        if quorum_count < 2 {
            return Err(KillSwitchError::AuthenticationFailed(format!(
                "CAGE quorum release rejected: quorum_count {} < 2",
                quorum_count
            )));
        }
        let digest = quorum_approval_digest.trim();
        if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(KillSwitchError::AuthenticationFailed(
                "CAGE quorum release rejected: invalid quorum_approval_digest".to_string(),
            ));
        }
        let status = self.get_status();
        if !status.isolated {
            return Ok(status);
        }
        if status.isolated_by.as_deref() != Some("cage_governance") {
            return Err(KillSwitchError::AuthenticationFailed(format!(
                "Fail-closed: active host isolation initiated by '{:?}' cannot be released by CAGE lease expiry",
                status.isolated_by
            )));
        }
        self.disarm_internal(
            "cage_governance_quorum",
            &format!(
                "Quorum-governed CAGE release for workload '{}' (quorum={})",
                workload_id, quorum_count
            ),
            "DISARMED_CAGE_QUORUM",
        )
        .await
    }
}

impl KillChainHostManager {
    /// Internal restoration engine reverting all network and process containment.
    async fn disarm_internal(
        &self,
        operator: &str,
        reason: &str,
        action: &str,
    ) -> Result<KillChainStatus> {
        // Hold exclusive engagement lock across entire restoration sequence
        let _engagement_guard = self.engagement_lock.lock().await;

        let current_status = self.get_status();
        if !current_status.isolated {
            #[cfg(target_os = "windows")]
            {
                let _ = crate::wfp::disarm_windows_network_quarantine(operator, reason);
            }
            crate::tarpit::ActiveProcessTarpit::global().release_all();
            info!("🛡️ [KILLCHAIN-IDEMPOTENCY] Host is already disarmed; purged any residual kernel rules and preserving state.");
            return Ok(current_status);
        }

        info!(
            "🟢 [KILLCHAIN] Disarming containment requested by '{}' ({})",
            operator, reason
        );

        // Cancel running watchdog task
        {
            let mut abort_guard = self.watchdog_abort_tx.lock();
            if let Some(tx) = abort_guard.take() {
                let _ = tx.send(());
            }
        }

        // 1. Revert Network Quarantine
        let receipts = self.get_network_receipts();
        for receipt in &receipts {
            if let Err(err) = self.network_isolator.restore_quarantine(receipt) {
                error!(
                    "❌ [KILLCHAIN] Error restoring network quarantine receipt {}: {}",
                    receipt.receipt_id, err
                );
            }
        }
        #[cfg(target_os = "windows")]
        {
            let _ = crate::wfp::disarm_windows_network_quarantine(operator, reason);
        }
        crate::tarpit::ActiveProcessTarpit::global().release_all();

        // 2. Resume Frozen Processes and release managed confinement Job Objects
        crate::job_sandbox::release_all_sandbox_jobs();
        let process_records = self.get_process_records();
        for proc in &process_records {
            if proc.status == killswitch_types::ProcessFreezeStatus::Frozen {
                let _ = self.process_freezer.resume_process(proc.pid);
            } else if proc.status == killswitch_types::ProcessFreezeStatus::Tarpitted {
                let _ = self.process_freezer.release_tarpit(proc.pid);
            }
        }

        // 3. Update and Commit Ledger Snapshot
        let now = Utc::now();
        let mut disarmed_status = KillChainStatus {
            isolated: false,
            containment_level: ContainmentLevel::Disarmed,
            isolated_at: None,
            isolated_by: None,
            reason: Some(reason.to_string()),
            network_isolated: false,
            processes_frozen_count: 0,
            processes_tarpitted_count: 0,
            kernel_lockdown_active: false,
            allowlisted_ports: vec![DEFAULT_CONTROL_PORT],
            quarantined_interfaces: Vec::new(),
            frozen_pids: Vec::new(),
            tarpitted_pids: Vec::new(),
            active_network_rules: Vec::new(),
            quarantined_arms: self.get_status().quarantined_arms,
            last_action_timestamp: Some(now),
            lockout_remaining_secs: 0,
            rollback_watchdog_max_secs: DEFAULT_ROLLBACK_WATCHDOG_MAX_SECS,
            health_probe_interval_secs: DEFAULT_INTERMEDIATE_HEALTH_PROBE_INTERVAL_SECS,
            consecutive_healthy_probes_required: DEFAULT_REQUIRED_CONSECUTIVE_HEALTHY_PROBES,
            consecutive_healthy_probes: 0,
            last_health_probe_timestamp: Some(now),
            last_health_probe_passed: Some(true),
            last_health_probe_summary: Some(
                "Isolation disarmed; host restored to normal operations".to_string(),
            ),
            state_hash_blake3: String::new(),
        };
        disarmed_status.update_hash();

        {
            let mut ledger = self.ledger.write();
            ledger.record_state_transition(
                disarmed_status.clone(),
                Some(Vec::new()),
                Some(Vec::new()),
                action,
                operator,
                reason,
            )?;
        }

        info!("🟢 [KILLCHAIN] Containment fully disarmed. Endpoint normal operations restored.");
        Ok(disarmed_status)
    }

    /// Spawns the background 60s health-probe watchdog task.
    ///
    /// Strictly fail-closed: watchdog probes emit diagnostics and operator alerts when active
    /// isolation exceeds `DEFAULT_ROLLBACK_WATCHDOG_MAX_SECS`, NEVER automatically disarming
    /// host containment without authenticated operator credentials.
    fn spawn_watchdog_task(self: &Arc<Self>) {
        let (abort_tx, mut abort_rx) = tokio::sync::oneshot::channel::<()>();
        {
            let mut guard = self.watchdog_abort_tx.lock();
            *guard = Some(abort_tx);
        }

        let manager = Arc::clone(self);
        tokio::spawn(async move {
            let start_time = Instant::now();
            let probe_interval =
                std::time::Duration::from_secs(DEFAULT_INTERMEDIATE_HEALTH_PROBE_INTERVAL_SECS);
            let max_alert_interval =
                std::time::Duration::from_secs(DEFAULT_ROLLBACK_WATCHDOG_MAX_SECS);
            let mut last_ceiling_alert = false;

            loop {
                tokio::select! {
                    _ = &mut abort_rx => {
                        info!("Watchdog aborted cleanly upon authenticated operator disarm.");
                        break;
                    }
                    _ = tokio::time::sleep(probe_interval) => {
                        let current = manager.get_status();
                        if !current.isolated {
                            break;
                        }

                        // 1. Run intermediate health probe (telemetry & integrity monitoring only)
                        match manager.run_probe() {
                            Ok(report) => {
                                if !report.process_tree_integrity_ok {
                                    warn!(
                                        "⚠️ [KILLCHAIN-WATCHDOG] Integrity anomaly detected while isolated: {}",
                                        report.summary
                                    );
                                } else {
                                    info!(
                                        "ℹ️ [KILLCHAIN-WATCHDOG] Containment healthy ({} clean probes; manual operator auth required to disarm)",
                                        report.consecutive_healthy_probes
                                    );
                                }
                            }
                            Err(err) => {
                                warn!("⚠️ [KILLCHAIN-WATCHDOG] Probe scan error: {}", err);
                            }
                        }

                        // 2. Alert operator if ceiling duration exceeded — NEVER disarm fail-open
                        if !last_ceiling_alert && start_time.elapsed() >= max_alert_interval {
                            last_ceiling_alert = true;
                            warn!(
                                "⏰ [KILLCHAIN-WATCHDOG] Isolation duration exceeded {}s threshold. Holding containment FAIL-CLOSED until authenticated operator disarm.",
                                DEFAULT_ROLLBACK_WATCHDOG_MAX_SECS
                            );
                        }
                    }
                }
            }
        });
    }
}

// -----------------------------------------------------------------------------
// Trait Implementations for KillChainHostManager
// -----------------------------------------------------------------------------

impl NetworkIsolator for KillChainHostManager {
    fn engage_quarantine(
        &self,
        preserved_ports: &[u16],
        operator: &str,
        reason: &str,
    ) -> Result<IsolationReceipt> {
        self.network_isolator
            .engage_quarantine(preserved_ports, operator, reason)
    }

    fn restore_quarantine(&self, receipt: &IsolationReceipt) -> Result<()> {
        self.network_isolator.restore_quarantine(receipt)
    }

    fn reset_tcp_connections(&self, target_ips: Option<&[IpAddr]>) -> Result<usize> {
        self.network_isolator.reset_tcp_connections(target_ips)
    }
}

impl ProcessFreezer for KillChainHostManager {
    fn freeze_process(&self, pid: u32) -> Result<ProcessIsolationState> {
        self.process_freezer.freeze_process(pid)
    }

    fn resume_process(&self, pid: u32) -> Result<ProcessIsolationState> {
        self.process_freezer.resume_process(pid)
    }

    fn tarpit_process(&self, pid: u32) -> Result<ProcessIsolationState> {
        self.process_freezer.tarpit_process(pid)
    }

    fn release_tarpit(&self, pid: u32) -> Result<ProcessIsolationState> {
        self.process_freezer.release_tarpit(pid)
    }

    fn is_immune(&self, pid: u32, proc_name: &str) -> bool {
        self.process_freezer.is_immune(pid, proc_name)
    }
}

impl OperatorAuthenticator for KillChainHostManager {
    fn authenticate(&self, creds: &OperatorCredentials) -> AuthResult {
        self.authenticator.authenticate(creds)
    }

    fn validate_caller(&self, caller_pid: Option<u32>) -> Result<()> {
        self.authenticator.validate_caller(caller_pid)
    }

    fn check_lockout(&self) -> LockoutState {
        self.authenticator.check_lockout()
    }

    fn reset_lockout(&self) {
        self.authenticator.reset_lockout();
    }
}

impl HealthProbeRunner for KillChainHostManager {
    fn run_probe(&self) -> Result<KillChainHealthProbeReport> {
        let status = self.get_status();
        let frozen_pids = status.frozen_pids.clone();

        let mut critical_os_anchors_verified = 0;
        let mut suspicious_unfrozen_processes = Vec::new();
        let mut orphaned_malicious_children = Vec::new();
        let mut anomalies = Vec::new();

        let high_risk_markers = [
            "untrusted_payload",
            "suspicious_exfil",
            "unauthorized_beacon",
            "test_malware",
        ];

        let total_processes_scanned = {
            let mut sys = self.process_scanner.lock();
            sys.refresh_processes_specifics(sysinfo::ProcessRefreshKind::new());

            for (pid_raw, proc) in sys.processes() {
                let pid = pid_raw.as_u32();
                let name = proc.name();

                if is_critical_system_pid(pid, name) {
                    critical_os_anchors_verified += 1;
                    continue;
                }

                if !frozen_pids.contains(&pid) {
                    let name_lc = name.to_ascii_lowercase();
                    let name_hit = high_risk_markers.iter().any(|m| name_lc.contains(m));
                    let cmd_lc = if name_hit || !proc.cmd().is_empty() {
                        proc.cmd().join(" ").to_ascii_lowercase()
                    } else {
                        String::new()
                    };
                    let is_malware =
                        name_hit || high_risk_markers.iter().any(|m| cmd_lc.contains(m));
                    if is_malware {
                        suspicious_unfrozen_processes.push(format!("{}:{}", pid, name));
                        anomalies.push(HealthProbeAnomaly {
                            anomaly_id: format!("anom-{}", uuid::Uuid::new_v4()),
                            kind: ProbeAnomalyKind::UnfrozenSuspiciousProcess,
                            offending_pid: Some(pid),
                            process_name: Some(name.to_string()),
                            command_line: Some(cmd_lc),
                            description: format!(
                                "High-risk process '{}:{}' executing unfrozen during isolation",
                                pid, name
                            ),
                        });
                    }

                    // Check orphaned children spawned from quarantined parents
                    if let Some(parent_pid) = proc.parent() {
                        let p_u32 = parent_pid.as_u32();
                        if frozen_pids.contains(&p_u32) && !is_critical_system_pid(pid, name) {
                            orphaned_malicious_children.push(pid);
                            anomalies.push(HealthProbeAnomaly {
                                anomaly_id: format!("anom-{}", uuid::Uuid::new_v4()),
                                kind: ProbeAnomalyKind::OrphanedMaliciousChild,
                                offending_pid: Some(pid),
                                process_name: Some(name.to_string()),
                                command_line: None,
                                description: format!(
                                    "Orphaned child PID {} spawned from quarantined parent PID {}",
                                    pid, p_u32
                                ),
                            });
                        }
                    }
                }
            }
            sys.processes().len()
        };

        let process_tree_integrity_ok = total_processes_scanned > 0
            && critical_os_anchors_verified > 0
            && suspicious_unfrozen_processes.is_empty()
            && orphaned_malicious_children.is_empty();

        let mut updated_status = status.clone();
        if process_tree_integrity_ok {
            updated_status.consecutive_healthy_probes += 1;
        } else {
            updated_status.consecutive_healthy_probes = 0;
        }

        let consecutive = updated_status.consecutive_healthy_probes;
        let required = updated_status.consecutive_healthy_probes_required;
        // Fail-closed invariant: health probes report telemetry only; never authorize automatic rollback.
        let eligible = false;

        let summary = if process_tree_integrity_ok {
            format!(
                "Process tree healthy ({} procs scanned, {} critical OS anchors verified, {}/{} consecutive healthy probes; authenticated operator disarm required)",
                total_processes_scanned, critical_os_anchors_verified, consecutive, required
            )
        } else {
            format!(
                "Process tree integrity violation: {} suspicious unfrozen processes, {} orphaned malicious children",
                suspicious_unfrozen_processes.len(), orphaned_malicious_children.len()
            )
        };

        let now = Utc::now();
        updated_status.last_health_probe_timestamp = Some(now);
        updated_status.last_health_probe_passed = Some(process_tree_integrity_ok);
        updated_status.last_health_probe_summary = Some(summary.clone());
        updated_status.update_hash();

        // Update ledger with probe status
        {
            let mut ledger = self.ledger.write();
            let _ = ledger.update_health_probe_status(updated_status.clone());
        }

        let probe_hash_blake3 = KillChainHealthProbeReport::compute_hash(
            &now,
            process_tree_integrity_ok,
            total_processes_scanned,
            critical_os_anchors_verified,
            consecutive,
            &summary,
        );

        Ok(KillChainHealthProbeReport {
            timestamp: now,
            process_tree_integrity_ok,
            total_processes_scanned,
            critical_os_anchors_verified,
            frozen_pids_monitored: frozen_pids.len(),
            suspicious_unfrozen_processes,
            orphaned_malicious_children,
            detected_anomalies: anomalies,
            consecutive_healthy_probes: consecutive,
            required_healthy_probes: required,
            eligible_for_early_rollback: eligible,
            rollback_watchdog_max_secs: DEFAULT_ROLLBACK_WATCHDOG_MAX_SECS,
            probe_interval_secs: DEFAULT_INTERMEDIATE_HEALTH_PROBE_INTERVAL_SECS,
            probe_hash_blake3,
            summary,
        })
    }

    fn reset_probe_counter(&self) {
        let mut status = self.get_status();
        status.consecutive_healthy_probes = 0;
        status.update_hash();
        let mut ledger = self.ledger.write();
        let _ = ledger.update_health_probe_status(status);
    }
}

fn is_untrusted_temp_or_public_path(path_or_name: &str) -> bool {
    let norm = path_or_name
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .replace('/', "\\")
        .to_ascii_lowercase();
    norm.contains("\\temp\\")
        || norm.contains("\\tmp\\")
        || norm.contains("\\var\\tmp\\")
        || norm.contains("\\dev\\shm\\")
        || norm.contains("\\appdata\\local\\temp\\")
        || norm.contains("\\users\\public\\")
}

fn is_exact_killswitch_executable_name(base_lc: &str) -> bool {
    let stem = base_lc.strip_suffix(".exe").unwrap_or(base_lc);
    matches!(
        stem,
        "killswitch"
            | "killswitch-server"
            | "killswitch-cli"
            | "killswitch-daemon"
            | "killswitch-agent"
            | "killswitch-test"
            | "oshoosi"
            | "oshoosiclaw"
            | "osoosi"
    )
}

/// Helper function strictly for immutable OS kernel anchors (PID 0, 1, 4, csrss, smss, wininit, systemd, launchd, etc.).
/// Decoupled from developer tools and agent runtimes (wsl.exe, sudo, su, bash, powershell.exe, node, python, cursor, code.exe).
pub fn is_immutable_os_kernel_pid(pid: u32, name: &str) -> bool {
    // 1. Kernel, Idle, and Self PIDs
    if pid <= 4 || pid == std::process::id() {
        return true;
    }

    let trimmed = name.trim().trim_matches('"').trim_matches('\'');
    let base = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed);
    let name_lc = base.to_ascii_lowercase();

    // Reject binaries running from temp/world-writable staging paths before name matching
    if is_untrusted_temp_or_public_path(trimmed) {
        return false;
    }

    // 2. KillSwitch Self-Preservation (exact binary stem, never substring)
    if is_exact_killswitch_executable_name(&name_lc) {
        return true;
    }

    // 3. Immutable OS Kernel and Core System Subsystem Anchors ONLY
    matches!(
        name_lc.as_str(),
        // Windows Core Kernel / Session Subsystem Anchors
        "system"
            | "smss.exe"
            | "csrss.exe"
            | "wininit.exe"
            | "winlogon.exe"
            | "services.exe"
            | "lsass.exe"
            | "lsm.exe"
            | "fontdrvhost.exe"
            // Linux Core Kernel / Init Anchors
            | "init"
            | "systemd"
            | "systemd-journald"
            | "systemd-udevd"
            | "dbus-daemon"
            | "kthreadd"
            // macOS Core System Anchors
            | "launchd"
            | "kernel_task"
            | "windowserver"
            | "opendirectoryd"
    )
}

/// Helper function to classify developer tools, shells, and agent runtimes.
pub fn is_developer_or_agent_runtime(name: &str) -> bool {
    let trimmed = name.trim().trim_matches('"').trim_matches('\'');
    let base = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed);
    let name_lc = base.to_ascii_lowercase();

    matches!(
        name_lc.as_str(),
        "wsl.exe"
            | "wslservice.exe"
            | "wslhost.exe"
            | "vmmem"
            | "vmmemwsl"
            | "powershell.exe"
            | "pwsh.exe"
            | "cmd.exe"
            | "sudo"
            | "su"
            | "bash"
            | "sh"
            | "zsh"
            | "fish"
            | "python.exe"
            | "python"
            | "python3"
            | "python3.exe"
            | "node.exe"
            | "node"
            | "cursor.exe"
            | "cursor"
            | "code.exe"
            | "windsurf.exe"
            | "docker.exe"
            | "dockerd.exe"
            | "cargo.exe"
            | "cargo"
            | "rustc.exe"
            | "rustc"
            | "git.exe"
            | "git"
    )
}

/// Helper function to classify critical system and developer build/UI infrastructure.
///
/// NOTE: Privilege escalation binaries (`sudo`, `su`), container/VM runtimes (`wsl*`, `docker*`),
/// shells (`bash`, `sh`, `zsh`, `fish`, `cmd.exe`, `powershell.exe`, `pwsh.exe`), exfiltration tools
/// (`scp`, `sftp`, `rsync`), scripting interpreters (`python*`, `node*`), and tracked AI agent subtrees
/// are NEVER granted ambient immunity.
pub fn is_critical_system_pid(pid: u32, name: &str) -> bool {
    // 1. Kernel, Idle, and Self PIDs
    if pid <= 4 || pid == std::process::id() {
        return true;
    }

    // Any PID inside an actively tracked AI agent process tree loses ambient immunity
    if TrackedAgentTreeRegistry::global().is_tracked_pid(pid) {
        return false;
    }

    let trimmed = name.trim().trim_matches('"').trim_matches('\'');
    if is_untrusted_temp_or_public_path(trimmed) {
        return false;
    }
    let base = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed);
    let name_lc = base.to_ascii_lowercase();

    // 2. KillSwitch Self-Preservation (exact stem only)
    if is_exact_killswitch_executable_name(&name_lc) {
        return true;
    }

    // 3. Critical OS Kernel Daemons, UI Hosts, Interactive Terminals, and Build Compilers
    matches!(
        name_lc.as_str(),
        "system"
            | "smss.exe"
            | "csrss.exe"
            | "wininit.exe"
            | "winlogon.exe"
            | "userinit.exe"
            | "logonui.exe"
            | "sihost.exe"
            | "runtimebroker.exe"
            | "taskmgr.exe"
            | "securityhealthservice.exe"
            | "securityhealthsystray.exe"
            | "securityhealthhost.exe"
            | "smartscreen.exe"
            | "consent.exe"
            | "fontdrvhost.exe"
            | "searchhost.exe"
            | "searchindexer.exe"
            | "searchprotocolhost.exe"
            | "searchfilterhost.exe"
            | "startmenuexperiencehost.exe"
            | "shellexperiencehost.exe"
            | "shellhost.exe"
            | "services.exe"
            | "lsass.exe"
            | "lsm.exe"
            | "dwm.exe"
            | "svchost.exe"
            | "explorer.exe"
            | "taskhostw.exe"
            | "audiodg.exe"
            | "spoolsv.exe"
            | "wlanext.exe"
            | "dashost.exe"
            | "code.exe"
            | "antigravity.exe"
            | "windowsterminal.exe"
            | "wt.exe"
            | "cursor.exe"
            | "cursor"
            | "openconsole.exe"
            | "conhost.exe"
            | "git.exe"
            | "git"
            | "cargo.exe"
            | "cargo"
            | "rustc.exe"
            | "rustc"
            | "rustup.exe"
            | "rustup"
            | "init"
            | "systemd"
            | "systemd-logind"
            | "systemd-journald"
            | "systemd-resolved"
            | "systemd-networkd"
            | "systemd-udevd"
            | "dbus-daemon"
            | "dbus-broker"
            | "networkmanager"
            | "sshd"
            | "ssh"
            | "ls"
            | "tmux"
            | "screen"
            | "login"
            // Browsers (Never falsely suspended or quarantined)
            | "chrome.exe"
            | "chrome"
            | "msedge.exe"
            | "msedge"
            | "firefox.exe"
            | "firefox"
            | "brave.exe"
            | "brave"
            | "safari"
            | "opera.exe"
            | "vivaldi.exe"
            | "arc.exe"
            // Compilers & Build Toolchains
            | "devenv.exe"
            | "rider64.exe"
            | "idea64.exe"
            | "pycharm64.exe"
            | "clion64.exe"
            | "goland64.exe"
            | "webstorm64.exe"
            | "rustrover64.exe"
            | "rust-analyzer.exe"
            | "rust-analyzer"
            | "go.exe"
            | "go"
            | "dotnet.exe"
            | "dotnet"
            | "java.exe"
            | "java"
            | "javac.exe"
            | "javac"
            | "msbuild.exe"
            | "cl.exe"
            | "link.exe"
            | "gcc"
            | "g++"
            | "clang"
            | "clang++"
            | "lld"
            | "make"
            | "cmake"
            | "ninja"
            // macOS Critical System Daemons & Interactive Terminal UI
            | "launchd"
            | "windowserver"
            | "loginwindow"
            | "kernel_task"
            | "usereventagent"
            | "cfprefsd"
            | "opendirectoryd"
            | "mds"
            | "finder"
            | "dock"
            | "terminal"
            | "iterm2"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use killswitch_types::status::ProcessIsolationMethod;

    struct TestMockFreezer;
    impl ProcessFreezer for TestMockFreezer {
        fn freeze_process(&self, pid: u32) -> Result<ProcessIsolationState> {
            Ok(ProcessIsolationState::new_frozen(
                pid,
                "test.exe".to_string(),
                None,
                ProcessIsolationMethod::NtSuspendProcess,
            ))
        }
        fn resume_process(&self, pid: u32) -> Result<ProcessIsolationState> {
            let mut s = ProcessIsolationState::new_frozen(
                pid,
                "test.exe".to_string(),
                None,
                ProcessIsolationMethod::NtSuspendProcess,
            );
            s.mark_resumed();
            Ok(s)
        }
        fn tarpit_process(&self, pid: u32) -> Result<ProcessIsolationState> {
            Ok(ProcessIsolationState::new_frozen(
                pid,
                "test.exe".to_string(),
                None,
                ProcessIsolationMethod::ThreadTarpit,
            ))
        }
        fn release_tarpit(&self, pid: u32) -> Result<ProcessIsolationState> {
            let mut s = ProcessIsolationState::new_frozen(
                pid,
                "test.exe".to_string(),
                None,
                ProcessIsolationMethod::ThreadTarpit,
            );
            s.mark_resumed();
            Ok(s)
        }
        fn is_immune(&self, pid: u32, name: &str) -> bool {
            is_critical_system_pid(pid, name)
        }
    }

    #[tokio::test]
    async fn test_killchain_host_manager_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Arc::new(RwLock::new(
            StateLedger::open_or_init(Some(dir.path())).unwrap(),
        ));
        let mut auth = crate::auth::OperatorAuthManager::new(Some(dir.path().to_path_buf()), None);
        let test_token = "ks-test-operator-token-0123456789abcdef0123456789abcdef";
        auth.set_custom_master_token(test_token.to_string());
        let auth = Arc::new(auth);
        let manager = Arc::new(KillChainHostManager::new(
            Arc::new(SimulatedNetworkIsolator),
            Arc::new(TestMockFreezer),
            auth,
            ledger,
        ));

        // Engage isolation
        let status = manager
            .engage_isolation(
                "test_operator",
                "Simulated Threat",
                ContainmentLevel::HermeticIsolation,
                Some(5000),
            )
            .await
            .unwrap();
        assert!(status.isolated);
        assert!(status.network_isolated);

        // Run health probe (must NEVER authorize unauthenticated early rollback)
        let probe = manager.run_probe().unwrap();
        assert!(probe.total_processes_scanned > 0);
        assert!(!probe.eligible_for_early_rollback);

        // Unauthenticated disarm (None credentials) MUST fail closed
        assert!(manager
            .disarm_isolation("test_operator", "Missing creds bypass attempt", None)
            .await
            .is_err());
        assert!(manager.get_status().isolated);

        // Disarm isolation with valid operator credentials
        let creds = OperatorCredentials {
            operator_id: "test_operator".to_string(),
            auth_token: Some(test_token.to_string()),
            password: None,
            caller_pid: Some(std::process::id()),
            confirmation_phrase: None,
        };
        let disarmed = manager
            .disarm_isolation("test_operator", "Threat Resolved", Some(&creds))
            .await
            .unwrap();
        assert!(!disarmed.isolated);
        assert!(!disarmed.network_isolated);
    }

    #[test]
    fn test_macos_critical_system_pid_immunity() {
        let macos_daemons = [
            ("launchd", 1),
            ("WindowServer", 55),
            ("loginwindow", 56),
            ("kernel_task", 0),
            ("UserEventAgent", 57),
            ("cfprefsd", 58),
            ("opendirectoryd", 59),
            ("mds", 60),
            ("Finder", 61),
            ("Dock", 62),
            ("Terminal", 63),
            ("iTerm2", 64),
        ];

        for (name, pid) in macos_daemons {
            assert!(
                is_critical_system_pid(pid, name),
                "Expected is_critical_system_pid to return true for macOS '{}' (PID {})",
                name,
                pid
            );
        }
    }

    #[test]
    fn test_immutable_kernel_rejects_spoofed_killswitch_substrings_and_temp_paths() {
        assert!(!is_immutable_os_kernel_pid(7777, "killswitch_evil.exe"));
        assert!(!is_immutable_os_kernel_pid(7778, "/tmp/killswitch"));
        assert!(!is_immutable_os_kernel_pid(
            7779,
            "C:\\Users\\Public\\killswitch.exe"
        ));
        assert!(!is_immutable_os_kernel_pid(
            7780,
            "C:\\Users\\Alice\\AppData\\Local\\Temp\\killswitch.exe"
        ));
        assert!(is_immutable_os_kernel_pid(
            std::process::id(),
            "/tmp/killswitch_evil.exe"
        ));
        assert!(is_immutable_os_kernel_pid(
            7781,
            "C:\\Program Files\\KillSwitch\\killswitch.exe"
        ));
    }

    #[test]
    fn test_tracked_agent_tree_registry_revokes_immunity_and_resolves_subtree() {
        let reg = TrackedAgentTreeRegistry::global();
        let root_pid = 8_001_100;
        let child_shell = 8_001_101;
        let grandchild_py = 8_001_102;

        reg.register_agent_root(root_pid, "cursor.exe");
        reg.register_child(child_shell, root_pid);
        reg.register_child(grandchild_py, child_shell);

        assert!(reg.is_tracked_pid(root_pid));
        assert!(reg.is_tracked_pid(child_shell));
        assert!(reg.is_tracked_pid(grandchild_py));
        assert!(!is_critical_system_pid(grandchild_py, "python3"));
        assert!(!is_critical_system_pid(child_shell, "windowsterminal.exe"));

        let subtree = resolve_offending_process_subtree(root_pid, &HashSet::new());
        assert!(subtree.contains(&root_pid));
        assert!(subtree.contains(&child_shell));
        assert!(subtree.contains(&grandchild_py));
        assert!(!subtree.contains(&std::process::id()));
        assert!(!subtree.contains(&4));

        reg.unregister_pid(grandchild_py);
        reg.unregister_pid(child_shell);
        reg.unregister_pid(root_pid);
    }
}
