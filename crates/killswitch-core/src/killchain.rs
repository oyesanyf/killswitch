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
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use sysinfo::System;
use tracing::{error, info, warn};

use crate::state_ledger::StateLedger;

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
    fn engage_quarantine(
        &self,
        ports: &[u16],
        op: &str,
        reason: &str,
    ) -> Result<IsolationReceipt> {
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

    fn reset_tcp_connections(
        &self,
        _target_ips: Option<&[IpAddr]>,
    ) -> Result<usize> {
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
        // Hold exclusive engagement lock across entire isolation sequence
        let _engagement_guard = self.engagement_lock.lock().await;

        // Stage 1: Validate calling process integrity
        self.authenticator.validate_caller(caller_pid)?;

        info!(
            "🚨 [KILLCHAIN] Engaging containment level '{:?}' requested by '{}' (reason: '{}')",
            level, operator, reason
        );

        let current_status = self.get_status();
        let has_active_wfp = self
            .get_network_receipts()
            .iter()
            .any(|r| !r.wfp_filter_ids.is_empty());
        if current_status.isolated && has_active_wfp && current_status.containment_level == level {
            info!("🛡️ [KILLCHAIN-IDEMPOTENCY] Host is already isolated at {:?} with active WFP filters; preserving state.", level);
            return Ok(current_status);
        }

        let now = Utc::now();
        let mut network_isolated = false;
        let mut network_receipts = Vec::new();
        let active_network_rules = Vec::new();

        let mut preserved_ports = crate::wfp::discover_active_control_ports();
        for &p in &[DEFAULT_CONTROL_PORT, 53, 67, 68, 546, 547] {
            if !preserved_ports.contains(&p) {
                preserved_ports.push(p);
            }
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
            let high_risk_markers = [
                "untrusted_payload",
                "suspicious_exfil",
                "unauthorized_beacon",
                "test_malware",
            ];

            let candidate_pids: Vec<u32> = {
                let mut sys = self.process_scanner.lock();
                sys.refresh_processes_specifics(sysinfo::ProcessRefreshKind::new());
                sys.processes()
                    .iter()
                    .filter_map(|(pid_raw, proc)| {
                        let pid = pid_raw.as_u32();
                        let name = proc.name();
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

            for pid in candidate_pids {
                match self.process_freezer.freeze_process(pid) {
                    Ok(state) => {
                        frozen_pids.push(pid);
                        process_records.push(state);
                    }
                    Err(err) => {
                        warn!("⚠️ [KILLCHAIN] Could not freeze PID {}: {}", pid, err);
                    }
                }
            }
            info!(
                "🚨 [KILLCHAIN] Suspended {} untrusted user-space processes.",
                frozen_pids.len()
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

    /// Disarms host containment and reverts all installed kernel filters and process suspensions.
    pub async fn disarm_isolation(
        &self,
        operator: &str,
        reason: &str,
        credentials: Option<&OperatorCredentials>,
    ) -> Result<KillChainStatus> {
        // Stage 1: Authenticate operator credentials if provided
        if let Some(creds) = credentials {
            self.authenticator.validate_caller(creds.caller_pid)?;
            let auth_res = self.authenticator.authenticate(creds);
            if !auth_res.is_success() {
                return Err(KillSwitchError::AuthenticationFailed(format!(
                    "{:?}",
                    auth_res
                )));
            }
        }

        self.disarm_internal(operator, reason, "DISARMED").await
    }

    /// Emergency disarm without authentication (for daemon shutdown or panic handler).
    pub async fn execute_unauthenticated_emergency_disarm(
        &self,
        reason: &str,
    ) -> Result<KillChainStatus> {
        info!(
            "🚨 [KILLCHAIN] Executing emergency unauthenticated host disarm: {}",
            reason
        );
        self.disarm_internal("SYSTEM_SHUTDOWN", reason, "DISARMED_SHUTDOWN")
            .await
    }
}

/// Global unconditional unauthenticated host disarm.
/// Called upon service stop/shutdown signal (`SERVICE_CONTROL_STOP`, `SIGTERM`, `SIGINT`),
/// daemon termination, panic, or test teardown to guarantee that the endpoint is never left quarantined.
pub fn execute_host_disarm_unauthenticated() -> Result<KillChainStatus> {
    info!("🚨 [DISARM-UNCONDITIONAL] Executing unconditional unauthenticated host disarm");

    // 1. Open State Ledger and inspect snapshot for active isolation artifacts
    let ledger_result = StateLedger::open_or_init(None);
    let (pids_to_resume, _network_receipts, quarantined_arms, ledger_opt) = match ledger_result {
        Ok(ledger) => {
            let mut pids = std::collections::HashSet::new();
            for &pid in &ledger.snapshot().status.frozen_pids {
                pids.insert(pid);
            }
            for proc in &ledger.snapshot().process_records {
                if proc.status == killswitch_types::ProcessFreezeStatus::Frozen {
                    pids.insert(proc.pid);
                }
            }
            let receipts = ledger.snapshot().network_receipts.clone();
            let arms = ledger.snapshot().status.quarantined_arms.clone();
            (pids, receipts, arms, Some(ledger))
        }
        Err(err) => {
            warn!(
                "⚠️ [DISARM-UNCONDITIONAL] Could not open state ledger: {}. Proceeding with global cleanup.",
                err
            );
            (
                std::collections::HashSet::new(),
                Vec::new(),
                std::collections::HashMap::new(),
                None,
            )
        }
    };

    // 2. Revert platform-native network quarantine
    #[cfg(target_os = "windows")]
    {
        let _ = crate::wfp::disarm_windows_network_quarantine(
            "UNCONDITIONAL_SHUTDOWN",
            "Automatic host disarm on service stop/shutdown",
        );
    }

    #[cfg(target_os = "linux")]
    {
        let isolator = crate::landlock::LinuxNetlinkIsolator::new();
        if _network_receipts.is_empty() {
            let dummy_receipt = IsolationReceipt::new(
                "shutdown-disarm".to_string(),
                killswitch_types::status::NetworkIsolationEngine::LinuxNetlink,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                0,
                "UNCONDITIONAL_SHUTDOWN".to_string(),
                "Automatic host disarm on service stop/shutdown".to_string(),
            );
            let _ = isolator.restore_quarantine(&dummy_receipt);
        } else {
            for receipt in &_network_receipts {
                let _ = isolator.restore_quarantine(receipt);
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let isolator = crate::pf::MacOsPfIsolator::new();
        if _network_receipts.is_empty() {
            let dummy_receipt = IsolationReceipt::new(
                "shutdown-disarm".to_string(),
                killswitch_types::status::NetworkIsolationEngine::DarwinPf,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                0,
                "UNCONDITIONAL_SHUTDOWN".to_string(),
                "Automatic host disarm on service stop/shutdown".to_string(),
            );
            let _ = isolator.restore_quarantine(&dummy_receipt);
        } else {
            for receipt in &_network_receipts {
                let _ = isolator.restore_quarantine(receipt);
            }
        }
    }

    // 3. Resume all frozen processes and release all tarpits
    // 3a. Release in-memory tarpits
    crate::tarpit::ActiveProcessTarpit::global().release_all();

    // 3b. Resume frozen OS processes discovered in state ledger
    let freezer = crate::freeze::NativeProcessFreezer::new();
    let mut pids_vec: Vec<u32> = pids_to_resume.into_iter().collect();
    pids_vec.sort_unstable();

    let mut resumed_count = 0;
    for &pid in &pids_vec {
        match freezer.resume_process(pid) {
            Ok(state) => {
                info!(
                    "🟢 [DISARM-UNCONDITIONAL] Resumed frozen process PID {} ({})",
                    pid, state.process_name
                );
                resumed_count += 1;
            }
            Err(err) => {
                warn!(
                    "⚠️ [DISARM-UNCONDITIONAL] Could not resume PID {}: {}",
                    pid, err
                );
            }
        }
    }
    if !pids_vec.is_empty() {
        info!(
            "🟢 [DISARM-UNCONDITIONAL] Process restoration completed: {}/{} frozen processes resumed.",
            resumed_count,
            pids_vec.len()
        );
    }

    // 4. Update and Commit Clean Disarmed State to State Ledger
    let now = Utc::now();
    let mut status = KillChainStatus {
        isolated: false,
        containment_level: ContainmentLevel::Disarmed,
        isolated_at: None,
        isolated_by: None,
        reason: Some("Automatic host disarm on service stop/shutdown signal".to_string()),
        network_isolated: false,
        processes_frozen_count: 0,
        processes_tarpitted_count: 0,
        kernel_lockdown_active: false,
        allowlisted_ports: vec![DEFAULT_CONTROL_PORT, 53, 67, 68, 546, 547],
        quarantined_interfaces: Vec::new(),
        frozen_pids: Vec::new(),
        tarpitted_pids: Vec::new(),
        active_network_rules: Vec::new(),
        quarantined_arms,
        last_action_timestamp: Some(now),
        lockout_remaining_secs: 0,
        rollback_watchdog_max_secs: DEFAULT_ROLLBACK_WATCHDOG_MAX_SECS,
        health_probe_interval_secs: DEFAULT_INTERMEDIATE_HEALTH_PROBE_INTERVAL_SECS,
        consecutive_healthy_probes_required: DEFAULT_REQUIRED_CONSECUTIVE_HEALTHY_PROBES,
        consecutive_healthy_probes: 0,
        last_health_probe_timestamp: Some(now),
        last_health_probe_passed: Some(true),
        last_health_probe_summary: Some(
            "Host disarmed unconditionally on service stop/shutdown signal".to_string(),
        ),
        state_hash_blake3: String::new(),
    };
    status.update_hash();

    // Ensure we commit using existing or newly opened ledger
    let ledger = match ledger_opt {
        Some(l) => Some(l),
        None => StateLedger::open_or_init(None).ok(),
    };

    if let Some(mut l) = ledger {
        let _ = l.record_state_transition(
            status.clone(),
            Some(Vec::new()),
            Some(Vec::new()),
            "DISARMED_UNCONDITIONAL",
            "SYSTEM_SHUTDOWN",
            "Automatic host disarm on service stop/shutdown signal",
        );
    }

    info!("🟢 [DISARM-UNCONDITIONAL] Host disarm completed successfully.");
    Ok(status)
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
            info!("🛡️ [KILLCHAIN-IDEMPOTENCY] Host is already disarmed; preserving state.");
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

        // 2. Resume Frozen Processes
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

    /// Spawns the background 60s health-probe and 30-minute failsafe watchdog task.
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
            let max_failsafe = std::time::Duration::from_secs(DEFAULT_ROLLBACK_WATCHDOG_MAX_SECS);

            loop {
                tokio::select! {
                    _ = &mut abort_rx => {
                        info!("Watchdog aborted cleanly upon manual disarm.");
                        break;
                    }
                    _ = tokio::time::sleep(probe_interval) => {
                        let current = manager.get_status();
                        if !current.isolated {
                            break;
                        }

                        // 1. Run intermediate health probe
                        match manager.run_probe() {
                            Ok(report) => {
                                if report.eligible_for_early_rollback {
                                    info!(
                                        "🟢 [KILLCHAIN-WATCHDOG] Process tree healthy across {}/{} probes. Executing automatic early rollback!",
                                        report.consecutive_healthy_probes, report.required_healthy_probes
                                    );
                                    let _ = manager.disarm_internal(
                                        "autonomous_health_probe_watchdog",
                                        "Early automatic rollback: process tree integrity verified across consecutive probes",
                                        "DISARMED_HEALTH_PROBE",
                                    ).await;
                                    break;
                                }
                            }
                            Err(err) => {
                                warn!("⚠️ [KILLCHAIN-WATCHDOG] Probe scan error: {}", err);
                            }
                        }

                        // 2. Check 30-minute dead-man failsafe ceiling
                        if start_time.elapsed() >= max_failsafe {
                            warn!("⏰ [KILLCHAIN-WATCHDOG] 30-minute hard ceiling reached. Enforcing automatic failsafe rollback!");
                            let _ = manager.disarm_internal(
                                "failsafe_watchdog",
                                "Automatic dead-man failsafe rollback (anti-hostage defense)",
                                "DISARMED_WATCHDOG_FAILSAFE",
                            ).await;
                            break;
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

    fn reset_tcp_connections(
        &self,
        target_ips: Option<&[IpAddr]>,
    ) -> Result<usize> {
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
        let eligible = consecutive >= required;

        let summary = if process_tree_integrity_ok {
            format!(
                "Process tree healthy ({} procs scanned, {} critical OS anchors verified, {}/{} consecutive healthy probes)",
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

/// Helper function to classify critical system and developer processes.
pub fn is_critical_system_pid(pid: u32, name: &str) -> bool {
    // 1. Kernel, Idle, and Self PIDs
    if pid <= 4 || pid == std::process::id() {
        return true;
    }

    let trimmed = name.trim().trim_matches('"').trim_matches('\'');
    let base = trimmed.rsplit(['\\', '/']).next().unwrap_or(trimmed);
    let name_lc = base.to_ascii_lowercase();

    // 2. KillSwitch Self-Preservation
    if name_lc.contains("killswitch")
        || name_lc.contains("osoosi")
        || name_lc.contains("oshoosi")
    {
        return true;
    }

    // 3. Exhaustive OS and Developer Binary Catalog
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
            | "openconsole.exe"
            | "conhost.exe"
            | "powershell.exe"
            | "pwsh.exe"
            | "cmd.exe"
            | "wsl.exe"
            | "wslservice.exe"
            | "wslhost.exe"
            | "vmmem"
            | "vmmemwsl"
            | "docker.exe"
            | "dockerd.exe"
            | "python.exe"
            | "python"
            | "python3"
            | "python3.exe"
            | "node.exe"
            | "node"
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
            | "tmux"
            | "screen"
            | "sudo"
            | "su"
            | "login"
            | "bash"
            | "sh"
            | "zsh"
            | "fish"
            | "ls"
            | "ssh"
            | "scp"
            | "sftp"
            | "rsync"
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
            // IDEs & Developer Toolchains
            | "cursor.exe"
            | "cursor"
            | "windsurf.exe"
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
            // macOS Critical System Daemons, UI & Developer Tools
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
        let auth = Arc::new(crate::auth::OperatorAuthManager::new(
            Some(dir.path().to_path_buf()),
            None,
        ));
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

        // Run health probe
        let probe = manager.run_probe().unwrap();
        assert!(probe.total_processes_scanned > 0);

        // Disarm isolation
        let disarmed = manager
            .disarm_isolation("test_operator", "Threat Resolved", None)
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
}
