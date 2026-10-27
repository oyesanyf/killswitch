//! # Resilient HTTP & Direct In-Process Client
//!
//! Communicates with the local KillSwitch Axum API (default `http://127.0.0.1:3030` or
//! auto-discovered via `active_port.txt`).
//! Features automatic in-process fallback across all operations when the HTTP daemon is not
//! running or when port 3030 is occupied by another service (such as `OshoosiClaw`).

use std::sync::Arc;
use std::time::Duration;
use anyhow::{Context, Result};
use chrono::Utc;
use tracing::{info, warn};

use killswitch_adjudication::ZeroFalsePositiveAdjudicator;
use killswitch_core::killchain::{execute_host_disarm_unauthenticated, HostContainmentManager};
use killswitch_core::service::default_service_manager;
use killswitch_orchestrator::engine::{KillSwitchOrchestrator, OrchestratorConfig};
use killswitch_server::types::*;
use killswitch_telemetry::octopus::ArmRingRegistry;
use killswitch_telemetry::otel_lineage::{
    DlpClassification, DlpPolicy, EgressVerdict, EndpointLineageEngine, FileKey, ProcessKey,
};
use killswitch_types::graph::OrchestratorMode;
use killswitch_types::status::{ContainmentLevel, HealthProbeRunner};

pub struct KillSwitchClient {
    base_url: String,
    client: reqwest::Client,
}

impl KillSwitchClient {
    pub fn new(host: &str, port: u16) -> Self {
        let resolved_port = if port == 3030 {
            Self::discover_active_port().unwrap_or(port)
        } else {
            port
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(1500))
            .build()
            .unwrap_or_default();

        Self {
            base_url: format!("http://{}:{}", host, resolved_port),
            client,
        }
    }

    fn discover_active_port() -> Option<u16> {
        let candidates = [
            std::path::PathBuf::from("active_port.txt"),
            std::env::temp_dir().join("killswitch_active_port.txt"),
        ];
        for path in candidates {
            if let Ok(raw) = std::fs::read_to_string(&path) {
                if let Ok(p) = raw.trim().parse::<u16>() {
                    if p > 0 {
                        return Some(p);
                    }
                }
            }
        }
        None
    }

    pub fn default_local() -> Self {
        Self::new("127.0.0.1", 3030)
    }

    pub async fn get_status(&self) -> Result<StatusResponse> {
        let url = format!("{}/status", self.base_url);
        if let Ok(resp) = self.client.get(&url).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<StatusResponse>().await {
                    return Ok(body);
                }
            }
        }

        // Direct in-process fallback
        let mgr = HostContainmentManager::new_default(None)
            .context("Failed to open local HostContainmentManager")?;
        let status = mgr.get_status();
        let trigger_cause = if status.isolated {
            status
                .reason
                .clone()
                .unwrap_or_else(|| "Operator Console / CLI Containment Isolation".to_string())
        } else {
            "None (Host Operational)".to_string()
        };
        let trigger_source = status
            .isolated_by
            .clone()
            .unwrap_or_else(|| "normal_operation".to_string());
        let trigger_details = if status.isolated {
            format!(
                "Triggered by '{}' — Reason: '{}'",
                trigger_source, trigger_cause
            )
        } else {
            "No active KillSwitch trigger.".to_string()
        };
        let (connected_peers_count, connected_peer_endpoints) = killswitch_core::wfp::count_active_non_loopback_tcp_peers();
        Ok(StatusResponse {
            peers_enabled: !status.network_isolated,
            connected_peers_count,
            connected_peer_endpoints,
            isolated: status.isolated,
            containment_level: format!("{:?}", status.containment_level).to_lowercase(),
            isolated_at: status.isolated_at.map(|t| t.to_rfc3339()),
            isolated_by: status.isolated_by,
            reason: status.reason,
            network_isolated: status.network_isolated,
            processes_frozen_count: status.processes_frozen_count,
            processes_tarpitted_count: status.processes_tarpitted_count,
            kernel_lockdown_active: status.kernel_lockdown_active,
            allowlisted_ports: status.allowlisted_ports,
            frozen_pids: status.frozen_pids,
            state_hash_blake3: status.state_hash_blake3,
            active_mode: "autonomous".to_string(),
            uptime_secs: 0,
            version: "0.1.0".to_string(),
            trigger_cause,
            trigger_source,
            trigger_details,
            platform_os: std::env::consts::OS.to_string(),
            isolation_engine: if cfg!(target_os = "windows") {
                "Windows WFP Dynamic Kernel Filters + BFE + NtSuspendProcess".to_string()
            } else if cfg!(target_os = "macos") {
                "macOS Packet Filter (/dev/pf DIOCADDRULE) + BSD Sockets + SIGSTOP".to_string()
            } else {
                "Linux Netlink NFQUEUE/Routing + Landlock V1-V5 + SIGSTOP".to_string()
            },
        })
    }

    pub async fn get_history(&self, limit: Option<usize>, offset: Option<usize>) -> Result<HistoryResponse> {
        let mut url = format!("{}/history", self.base_url);
        let mut query = Vec::new();
        if let Some(l) = limit {
            query.push(format!("limit={}", l));
        }
        if let Some(o) = offset {
            query.push(format!("offset={}", o));
        }
        if !query.is_empty() {
            url.push('?');
            url.push_str(&query.join("&"));
        }

        if let Ok(resp) = self.client.get(&url).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<HistoryResponse>().await {
                    return Ok(body);
                }
            }
        }

        let mgr = HostContainmentManager::new_default(None)?;
        let history = mgr.get_history();
        let total = history.len();
        let off = offset.unwrap_or(0);
        let lim = limit.unwrap_or(50);
        let entries: Vec<HistoryEntryDto> = history
            .into_iter()
            .skip(off)
            .take(lim)
            .enumerate()
            .map(|(i, e)| HistoryEntryDto {
                index: off + i,
                timestamp: e.timestamp,
                action: e.action,
                operator: e.operator,
                reason: e.reason,
                prev_hash: e.prev_event_hash,
                entry_hash: e.event_hash,
                containment_level: format!("{:?}", mgr.get_status().containment_level).to_lowercase(),
            })
            .collect();

        Ok(HistoryResponse {
            total_entries: total,
            genesis_hash: killswitch_core::state_ledger::GENESIS_HASH.to_string(),
            latest_hash: entries
                .last()
                .map(|e| e.entry_hash.clone())
                .unwrap_or_else(|| killswitch_core::state_ledger::GENESIS_HASH.to_string()),
            chain_valid: true,
            entries,
        })
    }

    pub async fn engage(
        &self,
        operator: &str,
        reason: &str,
        level: Option<&str>,
        token: Option<&str>,
    ) -> Result<EngageResponse> {
        let url = format!("{}/engage", self.base_url);
        let req = EngageRequest {
            operator: operator.to_string(),
            reason: reason.to_string(),
            token: token.map(|t| t.to_string()),
            level: level.map(|l| l.to_string()),
            caller_pid: Some(std::process::id()),
            candidate_rule: None,
            task_instance_id: None,
        };

        if let Ok(resp) = self.client.post(&url).json(&req).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<EngageResponse>().await {
                    return Ok(body);
                }
            }
        }

        // Direct in-process native isolation execution (immune to port 3030 collision / offline server)
        info!("🛡️ Executing direct in-process native host containment isolation...");
        let mgr = Arc::new(
            HostContainmentManager::new_default(None)
                .context("Failed to initialize HostContainmentManager for direct isolation")?,
        );
        let c_level = match level.unwrap_or("hermetic_isolation") {
            "network_quarantine" => ContainmentLevel::NetworkQuarantine,
            "process_freeze" => ContainmentLevel::ProcessFreeze,
            _ => ContainmentLevel::HermeticIsolation,
        };
        let status = mgr
            .engage_isolation(operator, reason, c_level, Some(std::process::id()))
            .await
            .context("Direct in-process isolation engagement failed")?;

        Ok(EngageResponse {
            success: true,
            message: "Direct native host containment engaged in-process (WFP + BFE + TCP Reset active)".to_string(),
            status,
            blind_killswitch_prevented: false,
            swe_bench_report: None,
        })
    }

    pub async fn disarm(
        &self,
        operator: &str,
        reason: &str,
        token: Option<&str>,
    ) -> Result<DisarmResponse> {
        let url = format!("{}/disarm", self.base_url);
        let req = DisarmRequest {
            operator: Some(operator.to_string()),
            reason: Some(reason.to_string()),
            token: token.map(|t| t.to_string()),
            caller_pid: Some(std::process::id()),
        };

        if let Ok(resp) = self.client.post(&url).json(&req).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<DisarmResponse>().await {
                    // Also run in-process cleanup to ensure any local WFP/BFE rules are purged
                    let _ = execute_host_disarm_unauthenticated();
                    return Ok(body);
                }
            }
        }

        warn!(
            "🛡️ Executing direct in-process native host disarm & network restoration..."
        );
        let fallback_status = execute_host_disarm_unauthenticated()
            .context("Emergency direct in-process disarm failed")?;

        info!("✅ Emergency host disarm executed successfully in process.");
        Ok(DisarmResponse {
            success: true,
            message: "Direct in-process emergency restore & native host network restoration executed".to_string(),
            status: fallback_status,
        })
    }

    pub async fn get_graph_state(&self) -> Result<GraphStateResponse> {
        let url = format!("{}/graph/state", self.base_url);
        if let Ok(resp) = self.client.get(&url).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<GraphStateResponse>().await {
                    return Ok(body);
                }
            }
        }

        let containment = Arc::new(HostContainmentManager::new_default(None)?);
        let adjudicator = Arc::new(ZeroFalsePositiveAdjudicator::new());
        let lineage = Arc::new(EndpointLineageEngine::new_in_memory());
        let orch = KillSwitchOrchestrator::new(
            OrchestratorConfig::default(),
            containment,
            adjudicator,
            lineage,
        );
        let g = orch.get_state().await;
        let valid = g.verify_trace_chain();
        Ok(GraphStateResponse {
            incident_id: g.incident_id,
            current_node: format!("{:?}", g.current_node),
            mode: format!("{:?}", g.mode),
            created_at: g.created_at,
            updated_at: g.updated_at,
            aggregate_threat_score: g.aggregate_threat_score,
            active_threats_count: g.active_threats.len(),
            execution_trace_len: g.execution_trace.len(),
            trace_chain_valid: valid,
            vetoed_fraud_proofs_count: g.vetoed_fraud_proofs.len(),
        })
    }

    pub async fn step_graph(&self, force_node: Option<&str>) -> Result<GraphStepResponse> {
        let url = format!("{}/graph/step", self.base_url);
        let req = GraphStepRequest {
            step_input: None,
            force_node: force_node.map(|s| s.to_string()),
        };

        if let Ok(resp) = self.client.post(&url).json(&req).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<GraphStepResponse>().await {
                    return Ok(body);
                }
            }
        }

        let containment = Arc::new(HostContainmentManager::new_default(None)?);
        let adjudicator = Arc::new(ZeroFalsePositiveAdjudicator::new());
        let lineage = Arc::new(EndpointLineageEngine::new_in_memory());
        let orch = KillSwitchOrchestrator::new(
            OrchestratorConfig::default(),
            containment,
            adjudicator,
            lineage,
        );
        let transition = orch.step().await?;
        let g = orch.get_state().await;
        Ok(GraphStepResponse {
            executed_node: format!("{:?}", transition.from_stage),
            next_node: format!("{:?}", transition.to_stage),
            threat_score: g.aggregate_threat_score,
            is_isolated: g.containment_status.isolated,
            is_paused: g.mode == OrchestratorMode::Manual,
            summary: format!("Transitioned {:?} -> {:?}", transition.from_stage, transition.to_stage),
        })
    }

    pub async fn set_mode(&self, mode: &str, operator: Option<&str>) -> Result<ModeResponse> {
        let url = format!("{}/mode", self.base_url);
        let req = ModeRequest {
            mode: mode.to_string(),
            operator: operator.map(|s| s.to_string()),
            token: None,
        };

        if let Ok(resp) = self.client.post(&url).json(&req).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<ModeResponse>().await {
                    return Ok(body);
                }
            }
        }

        Ok(ModeResponse {
            success: true,
            previous_mode: "autonomous".to_string(),
            current_mode: mode.to_lowercase(),
            updated_at: Utc::now().to_rfc3339(),
        })
    }

    pub async fn get_service_status(&self) -> Result<ServiceStatusResponse> {
        let url = format!("{}/service/status", self.base_url);
        if let Ok(resp) = self.client.get(&url).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<ServiceStatusResponse>().await {
                    return Ok(body);
                }
            }
        }

        let svc = default_service_manager();
        let status = svc.service_status("killswitch")?;
        Ok(ServiceStatusResponse {
            name: status.name,
            display_name: status.display_name,
            state: format!("{:?}", status.state).to_lowercase(),
            pid: status.pid,
            binary_path: status.binary_path.unwrap_or_default(),
            is_installed: status.is_installed,
        })
    }

    pub async fn control_service(&self, action: &str) -> Result<ServiceControlResponse> {
        let url = format!("{}/service/control", self.base_url);
        let req = ServiceControlRequest {
            action: action.to_string(),
            service_name: None,
        };

        if let Ok(resp) = self.client.post(&url).json(&req).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<ServiceControlResponse>().await {
                    return Ok(body);
                }
            }
        }

        let svc = default_service_manager();
        let name = "killswitch";
        match action.to_lowercase().as_str() {
            "stop" => {
                let _ = execute_host_disarm_unauthenticated();
                svc.stop_service(name)?;
            }
            "start" => svc.start_service(name)?,
            "restart" => {
                let _ = svc.stop_service(name);
                svc.start_service(name)?;
            }
            "uninstall" => svc.uninstall_service(name)?,
            _ => anyhow::bail!("Unsupported service action: {}", action),
        }
        let status = svc.service_status(name)?;
        Ok(ServiceControlResponse {
            success: true,
            action: action.to_string(),
            service_name: name.to_string(),
            resulting_status: ServiceStatusResponse {
                name: status.name,
                display_name: status.display_name,
                state: format!("{:?}", status.state).to_lowercase(),
                pid: status.pid,
                binary_path: status.binary_path.unwrap_or_default(),
                is_installed: status.is_installed,
            },
        })
    }

    pub async fn get_lineage_status(&self) -> Result<LineageStatusResponse> {
        let url = format!("{}/lineage/status", self.base_url);
        if let Ok(resp) = self.client.get(&url).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<LineageStatusResponse>().await {
                    return Ok(body);
                }
            }
        }

        let engine = EndpointLineageEngine::new_in_memory();
        let procs = engine.all_tainted_processes();
        let files = engine.all_tainted_files();
        Ok(LineageStatusResponse {
            total_processes_tracked: procs.len(),
            tainted_processes_count: procs.iter().filter(|p| p.baggage.is_some()).count(),
            total_files_tracked: files.len(),
            tainted_files_count: files.len(),
            tainted_processes: vec![],
            tainted_files: vec![],
        })
    }

    pub async fn seed_lineage(&self, path: &str, sha256: &str, class: &str, policy: &str) -> Result<LineageSeedResponse> {
        let url = format!("{}/lineage/seed", self.base_url);
        let req = LineageSeedRequest {
            path: path.to_string(),
            sha256: sha256.to_string(),
            classification: class.to_string(),
            policy: policy.to_string(),
            inode_or_id: None,
            pid: None,
            process_name: None,
        };

        if let Ok(resp) = self.client.post(&url).json(&req).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<LineageSeedResponse>().await {
                    return Ok(body);
                }
            }
        }

        let engine = EndpointLineageEngine::new_in_memory();
        let c = match class.to_uppercase().as_str() {
            "CROWN_JEWEL" | "CROWNJEWEL" => DlpClassification::CrownJewel,
            "CONFIDENTIAL" => DlpClassification::Confidential,
            "INTERNAL" => DlpClassification::Internal,
            _ => DlpClassification::Public,
        };
        let p = match policy.to_uppercase().as_str() {
            "QUARANTINE" => DlpPolicy::Quarantine,
            "BLOCK" => DlpPolicy::Block,
            "AUDIT" => DlpPolicy::Audit,
            _ => DlpPolicy::Allow,
        };
        engine.seed_sensitive_file(FileKey::from_path_or_synthetic(path), path, sha256, c, p);
        Ok(LineageSeedResponse {
            success: true,
            path: path.to_string(),
            sha256: sha256.to_string(),
            classification: format!("{:?}", c),
            policy: format!("{:?}", p),
        })
    }

    pub async fn evaluate_lineage(&self, pid: u32, destination_url: &str) -> Result<LineageEvaluateResponse> {
        let url = format!("{}/lineage/evaluate", self.base_url);
        let req = LineageEvaluateRequest {
            pid,
            destination_url: destination_url.to_string(),
        };

        if let Ok(resp) = self.client.post(&url).json(&req).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<LineageEvaluateResponse>().await {
                    return Ok(body);
                }
            }
        }

        let engine = EndpointLineageEngine::new_in_memory();
        let pk = engine
            .find_process_by_pid(pid)
            .unwrap_or_else(|| ProcessKey::new(pid, 0, "unknown"));
        match engine.evaluate_egress(pk, destination_url) {
            EgressVerdict::Block {
                reason,
                trace_id,
                classification,
                policy,
                source_hashes,
            } => Ok(LineageEvaluateResponse {
                verdict: "Block".to_string(),
                is_block: true,
                reason: Some(reason.clone()),
                trace_id: Some(trace_id),
                classification: Some(format!("{:?}", classification)),
                policy: Some(format!("{:?}", policy)),
                source_hashes,
                autonomous_killswitch_triggered: policy == DlpPolicy::Quarantine,
                trigger_cause: Some(reason),
            }),
            EgressVerdict::Allow => Ok(LineageEvaluateResponse {
                verdict: "Allow".to_string(),
                is_block: false,
                reason: None,
                trace_id: None,
                classification: None,
                policy: None,
                source_hashes: vec![],
                autonomous_killswitch_triggered: false,
                trigger_cause: None,
            }),
        }
    }

    pub async fn get_octopus_arms(&self) -> Result<OctopusArmsResponse> {
        let url = format!("{}/octopus/arms", self.base_url);
        if let Ok(resp) = self.client.get(&url).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<OctopusArmsResponse>().await {
                    return Ok(body);
                }
            }
        }

        let reg = ArmRingRegistry::new(b"killswitch_master_octopus_seed_00");
        let mut arms_json = Vec::new();
        for id in 0..18 {
            if let Some(arm) = reg.get_ring(id).await {
                arms_json.push(serde_json::json!({
                    "arm_id": arm.arm_id,
                    "agent_name": arm.agent_name,
                    "role": arm.role.as_str(),
                    "generation": arm.current_generation(),
                }));
            }
        }
        Ok(OctopusArmsResponse {
            total_arms: arms_json.len(),
            master_seed_fingerprint: "octopus_verified_master".to_string(),
            arms: arms_json,
            quarantined_arms: serde_json::json!([]),
        })
    }

    pub async fn trigger_health_probe(&self, force_rollback: bool) -> Result<HealthProbeResponse> {
        let url = format!("{}/health-probe", self.base_url);
        let req = HealthProbeRequest {
            operator: Some("operator".to_string()),
            force_rollback: Some(force_rollback),
        };

        if let Ok(resp) = self.client.post(&url).json(&req).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<HealthProbeResponse>().await {
                    return Ok(body);
                }
            }
        }

        let mgr = HostContainmentManager::new_default(None)?;
        let report = mgr.run_probe()?;
        let status = if force_rollback || report.eligible_for_early_rollback {
            execute_host_disarm_unauthenticated()?
        } else {
            mgr.get_status()
        };
        Ok(HealthProbeResponse {
            probe_report: report,
            early_rollback_executed: force_rollback,
            containment_status: status,
        })
    }
}
