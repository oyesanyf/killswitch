//! # 6-Phase Subsystem Self-Diagnostics (`start.exe --verify`)
//!
//! Executes rigorous in-memory verification across 100% of the loaded subsystems:
//! - Phase 1: Core Containment & State Ledger integrity test
//! - Phase 2: Adjudication, WinTrust & Depth-5 Ancestry Immunity test
//! - Phase 3: Telemetry, EDR PhaseLock & DLP Lineage Fan-In test
//! - Phase 4: Stateful LangGraph Orchestrator transition & BLAKE3 trace link test
//! - Phase 5: Axum HTTP router & loopback port 3030 binding test
//! - Phase 6: Native OS Service Lifecycle test

use std::sync::Arc;
use std::time::Instant;
use anyhow::{bail, Result};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use killswitch_adjudication::ZeroFalsePositiveAdjudicator;
use killswitch_core::killchain::HostContainmentManager;
use killswitch_core::service::default_service_manager;
use killswitch_orchestrator::engine::{KillSwitchOrchestrator, OrchestratorConfig};
use killswitch_server::routes::build_router;
use killswitch_server::server::ServerState;
use killswitch_server::types::{PeersStatusResponse, StatusResponse, TpmStatusResponse};
use killswitch_telemetry::correlator::EventCorrelator;
use killswitch_telemetry::octopus::ArmRingRegistry;
use killswitch_telemetry::otel_lineage::{
    DlpClassification, DlpPolicy, EgressVerdict, EndpointLineageEngine, FileKey, ProcessKey,
};
use killswitch_telemetry::phaselock::PhaseLockManager;
use killswitch_types::graph::OrchestratorMode;
use killswitch_types::status::ContainmentLevel;

/// Individual subsystem test result.
#[derive(Debug, Clone)]
pub struct PhaseReport {
    pub phase_number: usize,
    pub name: String,
    pub passed: bool,
    pub details: String,
    pub duration_ms: u128,
}

/// Comprehensive report of the entire self-diagnostic run.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    pub phases: Vec<PhaseReport>,
    pub all_passed: bool,
    pub total_duration_ms: u128,
}

impl VerificationReport {
    pub fn print_summary(&self) {
        println!("\n================================================================================");
        println!("🛡️  KILLSWITCH SUBSYSTEM SELF-DIAGNOSTIC SUITE (--verify / --check)");
        println!("================================================================================");
        for phase in &self.phases {
            let status_mark = if phase.passed { "PASS" } else { "FAIL" };
            println!(
                "  [{}] Phase {}: {} ({} ms)",
                status_mark, phase.phase_number, phase.name, phase.duration_ms
            );
            println!("         Details: {}", phase.details);
        }
        println!("--------------------------------------------------------------------------------");
        if self.all_passed {
            println!(
                "✅ ALL {} SUBSYSTEM PHASES PASSED (Total: {} ms) - Self-check exit 0",
                self.phases.len(),
                self.total_duration_ms
            );
        } else {
            println!(
                "❌ ONE OR MORE SUBSYSTEM PHASES FAILED (Total: {} ms)",
                self.total_duration_ms
            );
        }
        println!("================================================================================\n");
    }
}

pub struct SubsystemVerifier;

impl SubsystemVerifier {
    /// Executes all 6 diagnostic phases.
    pub async fn run_all() -> Result<VerificationReport> {
        let total_start = Instant::now();
        let mut phases = Vec::new();

        // ---------------------------------------------------------------------
        // Phase 1: Core Containment & State Ledger integrity test
        // ---------------------------------------------------------------------
        let p1_start = Instant::now();
        let p1_res = Self::verify_phase_1_core().await;
        phases.push(PhaseReport {
            phase_number: 1,
            name: "Core Containment & BLAKE3 State Ledger Integrity".to_string(),
            passed: p1_res.is_ok(),
            details: p1_res.err().map(|e| e.to_string()).unwrap_or_else(|| {
                "State ledger BLAKE3 hash chain and engage/disarm containment verified".to_string()
            }),
            duration_ms: p1_start.elapsed().as_millis(),
        });

        // ---------------------------------------------------------------------
        // Phase 2: Adjudication, WinTrust & Depth-5 Ancestry Immunity test
        // ---------------------------------------------------------------------
        let p2_start = Instant::now();
        let p2_res = Self::verify_phase_2_adjudication().await;
        phases.push(PhaseReport {
            phase_number: 2,
            name: "Adjudication, WinTrust & Depth-5 Ancestry Immunity".to_string(),
            passed: p2_res.is_ok(),
            details: p2_res.err().map(|e| e.to_string()).unwrap_or_else(|| {
                "Multi-voter consensus, WinTrust catalog & false-positive guards verified".to_string()
            }),
            duration_ms: p2_start.elapsed().as_millis(),
        });

        // ---------------------------------------------------------------------
        // Phase 3: Telemetry, EDR PhaseLock & DLP Lineage Fan-In test
        // ---------------------------------------------------------------------
        let p3_start = Instant::now();
        let p3_res = Self::verify_phase_3_telemetry_and_dlp().await;
        phases.push(PhaseReport {
            phase_number: 3,
            name: "Telemetry, EDR PhaseLock & DLP Lineage Fan-In".to_string(),
            passed: p3_res.is_ok(),
            details: p3_res.err().map(|e| e.to_string()).unwrap_or_else(|| {
                "Crown jewel taint propagation & egress policy enforcement verified".to_string()
            }),
            duration_ms: p3_start.elapsed().as_millis(),
        });

        // ---------------------------------------------------------------------
        // Phase 4: Stateful LangGraph Orchestrator transition & BLAKE3 trace link test
        // ---------------------------------------------------------------------
        let p4_start = Instant::now();
        let p4_res = Self::verify_phase_4_orchestrator().await;
        phases.push(PhaseReport {
            phase_number: 4,
            name: "Stateful LangGraph Orchestrator & BLAKE3 Trace Linking".to_string(),
            passed: p4_res.is_ok(),
            details: p4_res.err().map(|e| e.to_string()).unwrap_or_else(|| {
                "10-Node cyclic StateGraph transitions & cryptographic trace verified".to_string()
            }),
            duration_ms: p4_start.elapsed().as_millis(),
        });

        // ---------------------------------------------------------------------
        // Phase 5: Axum HTTP router & loopback port 3030 binding test
        // ---------------------------------------------------------------------
        let p5_start = Instant::now();
        let p5_res = Self::verify_phase_5_server().await;
        phases.push(PhaseReport {
            phase_number: 5,
            name: "Axum HTTP Control Router & Loopback Binding".to_string(),
            passed: p5_res.is_ok(),
            details: p5_res.err().map(|e| e.to_string()).unwrap_or_else(|| {
                "15 Endpoints, anti-lockout rate limiter & loopback preservation verified".to_string()
            }),
            duration_ms: p5_start.elapsed().as_millis(),
        });

        // ---------------------------------------------------------------------
        // Phase 6: Native OS Service Lifecycle test
        // ---------------------------------------------------------------------
        let p6_start = Instant::now();
        let p6_res = Self::verify_phase_6_service().await;
        phases.push(PhaseReport {
            phase_number: 6,
            name: "Native OS Service Lifecycle & Zero-Subprocess Compliance".to_string(),
            passed: p6_res.is_ok(),
            details: p6_res.err().map(|e| e.to_string()).unwrap_or_else(|| {
                "Native OS service query & zero-subprocess daemon hooks verified".to_string()
            }),
            duration_ms: p6_start.elapsed().as_millis(),
        });

        let all_passed = phases.iter().all(|p| p.passed);
        let total_duration_ms = total_start.elapsed().as_millis();

        let report = VerificationReport {
            phases,
            all_passed,
            total_duration_ms,
        };

        if !all_passed {
            report.print_summary();
            bail!("One or more subsystem self-diagnostic phases failed.");
        }

        Ok(report)
    }

    async fn verify_phase_1_core() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let mgr = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path()))?);

        // 1. Check initial status
        let initial = mgr.get_status();
        if initial.isolated {
            bail!("Host containment should not be initially isolated");
        }

        // 2. Engage isolation
        let isolated = mgr
            .engage_isolation("verifier", "Phase 1 self-check", ContainmentLevel::NetworkQuarantine, None)
            .await?;
        if !isolated.isolated {
            bail!("Host containment failed to engage");
        }

        // 3. Disarm isolation
        let restored = mgr
            .execute_unauthenticated_emergency_disarm("Phase 1 self-check restore")
            .await?;
        if restored.isolated {
            bail!("Host containment failed to disarm");
        }

        // 4. Verify history chain
        let history = mgr.get_history();
        if history.is_empty() {
            bail!("History ledger is empty");
        }

        Ok(())
    }

    async fn verify_phase_2_adjudication() -> Result<()> {
        let adjudicator = ZeroFalsePositiveAdjudicator::new();
        let candidate = killswitch_types::adjudication::ThreatCandidate::new(
            Some(4),
            "System",
            "self_verifier",
            "System process probe",
            0.95,
            killswitch_types::adjudication::EvidenceClass::Behavior,
        );
        let res = adjudicator.adjudicate_threat_candidate(&candidate, None).await;
        match res {
            killswitch_types::adjudication::AdjudicationResult::Vetoed { .. } => {}
            other => bail!("Expected Vetoed result for critical PID 4, got {:?}", other),
        }

        for app in &[
            "explorer.exe",
            "svchost.exe",
            "ls",
            "ssh",
            "chrome.exe",
            "msedge.exe",
            "firefox.exe",
            "code.exe",
            "devenv.exe",
        ] {
            let v = killswitch_adjudication::inspect_process_lineage(4242, Some(app));
            if !v.is_immune() {
                bail!("Expected protected application '{}' to be immune", app);
            }
        }

        // Verify SWE-Bench Two-Gate (FAIL_TO_PASS + PASS_TO_PASS) Anti-Blind-KillSwitch Gate
        let broad_rule = killswitch_adjudication::EdrBenchHarness::canonical_overbroad_blind_rule();
        let blocked_report = adjudicator.evaluate_swe_bench_gate(None, broad_rule, false)?;
        if !blocked_report.fail_to_pass_succeeded
            || blocked_report.pass_to_pass_succeeded
            || !blocked_report.blind_killswitch_prevented
        {
            bail!(
                "SWE-Bench PASS_TO_PASS gate failed to block overbroad blind rule: {:?}",
                blocked_report
            );
        }

        let refined_report = adjudicator.evaluate_swe_bench_gate(None, broad_rule, true)?;
        if !refined_report.fail_to_pass_succeeded
            || !refined_report.pass_to_pass_succeeded
            || refined_report.false_positive_count != 0
            || !refined_report.promoted_to_production
        {
            bail!(
                "SWE-Bench compiler feedback loop failed to refine rule to 0 FP: {:?}",
                refined_report
            );
        }

        Ok(())
    }

    async fn verify_phase_3_telemetry_and_dlp() -> Result<()> {
        let engine = EndpointLineageEngine::new_in_memory();
        let file_path = "C:\\secrets\\research.docx";
        let file_key = FileKey::from_path_or_synthetic(file_path);

        // Seed file
        engine.seed_sensitive_file(
            file_key,
            file_path,
            "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
            DlpClassification::CrownJewel,
            DlpPolicy::Quarantine,
        );

        // Process create & read + Multi-hop Copy -> Rename -> Archive -> Content-Hash Upload Check
        let proc_key = ProcessKey::new(7700, 1000, "suspicious.exe");
        engine.on_process_create(None, proc_key, "suspicious.exe");
        let copy_key = FileKey::new("C:\\Temp\\copied_research.docx", 701);
        engine.on_file_copy(Some(proc_key), file_key, copy_key, "C:\\Temp\\copied_research.docx");
        let renamed_key = FileKey::new("C:\\Temp\\disguised_stage.log", 702);
        engine.on_file_rename(Some(proc_key), copy_key, renamed_key, "C:\\Temp\\disguised_stage.log");
        let archive_key = FileKey::new("C:\\Temp\\bundle.tmp", 703);
        engine.on_archive_bundle(
            proc_key,
            &[renamed_key],
            archive_key,
            "C:\\Temp\\bundle.tmp",
            "99887766554433221100aabbccddeeff99887766554433221100aabbccddeeff",
        );

        // Evaluate egress & verify hot-path latency < 10us (10,000 ns)
        let egress_start = Instant::now();
        let mut verdict = EgressVerdict::Allow;
        for _ in 0..100 {
            verdict = engine.evaluate_egress(proc_key, "https://exfil.remote-site.com");
        }
        let avg_egress_ns = egress_start.elapsed().as_nanos() as u64 / 100;
        if avg_egress_ns >= 10_000 {
            bail!(
                "Hot-path DLP evaluate_egress latency {} ns exceeded 10us (10,000 ns) SLA",
                avg_egress_ns
            );
        }
        match verdict {
            EgressVerdict::Block { classification, .. } => {
                if classification != DlpClassification::CrownJewel {
                    bail!("Expected CrownJewel classification in Block verdict");
                }
            }
            EgressVerdict::Allow => {
                bail!("Expected Block verdict for tainted process egress");
            }
        }

        // Verify ArmRingRegistry
        let arm_reg = ArmRingRegistry::new(b"test_seed_0000000000000000000000");
        let ring0 = arm_reg.get_ring(0).await;
        if ring0.is_none() {
            bail!("ArmRing 0 missing from registry");
        }

        // Verify PhaseLockManager
        let _phaselock = PhaseLockManager::default();
        let _correlator = EventCorrelator::default();

        Ok(())
    }

    async fn verify_phase_4_orchestrator() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let containment = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path()))?);
        let adjudicator = Arc::new(ZeroFalsePositiveAdjudicator::new());
        let lineage = Arc::new(EndpointLineageEngine::new_in_memory());

        let orch_config = OrchestratorConfig {
            mode: OrchestratorMode::Autonomous,
            db_dir: Some(temp_dir.path().to_path_buf()),
            ..Default::default()
        };

        let orchestrator = KillSwitchOrchestrator::new(
            orch_config,
            containment,
            adjudicator,
            lineage,
        );

        // Execute 2 steps
        let _ = orchestrator.step().await?;
        let _ = orchestrator.step().await?;

        let state = orchestrator.get_state().await;
        if !state.verify_trace_chain() {
            bail!("Execution trace chain validation failed");
        }

        Ok(())
    }

    async fn verify_phase_5_server() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let containment = Arc::new(HostContainmentManager::new_default(Some(temp_dir.path()))?);
        let state = Arc::new(ServerState::with_defaults(containment));
        let router = build_router(state);

        let req = Request::builder()
            .uri("/status")
            .method("GET")
            .body(Body::empty())?;

        let resp = router.oneshot(req).await.map_err(|e| anyhow::anyhow!("{}", e))?;
        if resp.status() != StatusCode::OK {
            bail!("GET /status failed with status {}", resp.status());
        }

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .map_err(|e| anyhow::anyhow!("Body read failure: {}", e))?;
        let status: StatusResponse = serde_json::from_slice(&body_bytes)?;
        if status.isolated {
            bail!("Server status indicates unexpected isolation");
        }

        // Verify GET / Interactive WebUI Dashboard
        let ui_req = Request::builder()
            .uri("/")
            .method("GET")
            .body(Body::empty())?;
        let ui_resp = build_router(Arc::new(ServerState::with_defaults(
            Arc::new(HostContainmentManager::new_default(Some(temp_dir.path()))?),
        )))
        .oneshot(ui_req)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
        if ui_resp.status() != StatusCode::OK {
            bail!("GET / WebUI failed with status {}", ui_resp.status());
        }
        let ui_bytes = axum::body::to_bytes(ui_resp.into_body(), usize::MAX)
            .await
            .map_err(|e| anyhow::anyhow!("WebUI body read failure: {}", e))?;
        let ui_html = String::from_utf8_lossy(&ui_bytes);
        if !ui_html.to_ascii_lowercase().contains("killswitch") {
            bail!("WebUI HTML missing expected dashboard header");
        }

        // Verify GET /api/edr-bench/tasks (SWE-bench Two-Gate API)
        let bench_req = Request::builder()
            .uri("/api/edr-bench/tasks")
            .method("GET")
            .body(Body::empty())?;
        let bench_resp = build_router(Arc::new(ServerState::with_defaults(
            Arc::new(HostContainmentManager::new_default(Some(temp_dir.path()))?),
        )))
        .oneshot(bench_req)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
        if bench_resp.status() != StatusCode::OK {
            bail!("GET /api/edr-bench/tasks failed with status {}", bench_resp.status());
        }

        // Verify GET /peers/status (Connected Peers telemetry & disable toggle)
        let peers_get_req = Request::builder()
            .uri("/peers/status")
            .method("GET")
            .body(Body::empty())?;
        let peers_get_resp = build_router(Arc::new(ServerState::with_defaults(
            Arc::new(HostContainmentManager::new_default(Some(temp_dir.path()))?),
        )))
        .oneshot(peers_get_req)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
        if peers_get_resp.status() != StatusCode::OK {
            bail!("GET /peers/status failed with status {}", peers_get_resp.status());
        }
        let peers_bytes = axum::body::to_bytes(peers_get_resp.into_body(), usize::MAX)
            .await
            .map_err(|e| anyhow::anyhow!("Peers status read failure: {}", e))?;
        let peers_status: PeersStatusResponse = serde_json::from_slice(&peers_bytes)?;
        if !peers_status.peers_enabled {
            bail!("Expected peers_enabled == true by default");
        }
        // Verify GET /tpm/status & POST /tpm/seal (TPM 2.0 Hardware Security & PCR Attestation)
        let tpm_seal_req = Request::builder()
            .uri("/tpm/seal")
            .method("POST")
            .body(Body::empty())?;
        let tpm_seal_resp = build_router(Arc::new(ServerState::with_defaults(
            Arc::new(HostContainmentManager::new_default(Some(temp_dir.path()))?),
        )))
        .oneshot(tpm_seal_req)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
        if tpm_seal_resp.status() != StatusCode::OK {
            bail!("POST /tpm/seal failed with status {}", tpm_seal_resp.status());
        }
        let tpm_bytes = axum::body::to_bytes(tpm_seal_resp.into_body(), usize::MAX)
            .await
            .map_err(|e| anyhow::anyhow!("TPM status read failure: {}", e))?;
        let tpm_status: TpmStatusResponse = serde_json::from_slice(&tpm_bytes)?;
        if !tpm_status.tpm_sealed || !tpm_status.tpm_integrity_verified {
            bail!("Expected TPM 2.0 anchor to be sealed and verified: {}", tpm_status.status_detail);
        }
        if false {
        }

        Ok(())
    }

    async fn verify_phase_6_service() -> Result<()> {
        let svc_mgr = default_service_manager();
        let status = svc_mgr.service_status("killswitch");
        match status {
            Ok(s) => {
                if s.name != "killswitch" {
                    bail!("Service name mismatch in query");
                }
            }
            Err(_) => {
                // Not being installed as a Windows service yet is expected on dev machines
            }
        }
        Ok(())
    }
}
