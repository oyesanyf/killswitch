//! # CLI Command Handlers & Formatters

use anyhow::{bail, Result};
use crate::client::KillSwitchClient;
use crate::verify::SubsystemVerifier;

pub async fn handle_status(client: &KillSwitchClient) -> Result<()> {
    let status = client.get_status().await?;
    println!("\n================================================================================");
    println!("🛡️  KILLSWITCH SECURITY AGENT STATUS");
    println!("================================================================================");
    println!("  Isolated:               {}", if status.isolated { "YES (HOST CONTAINED)" } else { "NO (Normal Operation)" });
    println!("  Containment Level:      {}", status.containment_level);
    println!("  Active Mode:            {}", status.active_mode);
    println!("  Uptime:                 {} seconds", status.uptime_secs);
    println!("  Version:                {}", status.version);
    println!("  State Hash (BLAKE3):    {}", status.state_hash_blake3);
    println!("  Network Isolated:       {}", status.network_isolated);
    println!("  Processes Frozen:       {}", status.processes_frozen_count);
    println!("  Processes Tarpitted:    {}", status.processes_tarpitted_count);
    println!("  Kernel Lockdown Active: {}", status.kernel_lockdown_active);
    if !status.platform_os.is_empty() {
        println!("  Platform / OS Engine:   {} ({})", status.platform_os, status.isolation_engine);
    }
    if !status.trigger_cause.is_empty() {
        println!("  KillSwitch Root Cause:  {}", status.trigger_cause);
        println!("  Trigger Source / Voter: {}", status.trigger_source);
        println!("  Trigger Forensics:      {}", status.trigger_details);
    }
    if let Some(iso_at) = status.isolated_at {
        println!("  Isolated At:            {}", iso_at);
    }
    if let Some(iso_by) = status.isolated_by {
        println!("  Isolated By:            {}", iso_by);
    }
    if let Some(reason) = status.reason {
        println!("  Reason:                 {}", reason);
    }
    if !status.allowlisted_ports.is_empty() {
        println!("  Allowlisted Ports:      {:?}", status.allowlisted_ports);
    }
    if !status.frozen_pids.is_empty() {
        println!("  Frozen PIDs:            {:?}", status.frozen_pids);
    }
    println!("================================================================================\n");
    Ok(())
}

pub async fn handle_isolate(
    client: &KillSwitchClient,
    operator: &str,
    reason: &str,
    level: Option<&str>,
    token: Option<&str>,
) -> Result<()> {
    println!("🚨 Initiating Host Containment Isolation...");
    let resp = client.engage(operator, reason, level, token).await?;
    println!("✅ Containment Engaged: {}", resp.message);
    println!("   Level: {:?}", resp.status.containment_level);
    println!("   State Hash: {}", resp.status.state_hash_blake3);
    Ok(())
}

pub async fn handle_restore(
    client: &KillSwitchClient,
    operator: &str,
    reason: &str,
    token: Option<&str>,
) -> Result<()> {
    println!("🛡️  Initiating Host Disarm & Endpoint Restoration...");
    let resp = client.disarm(operator, reason, token).await?;
    println!("✅ Disarm Successful: {}", resp.message);
    println!("   Current Level: {:?}", resp.status.containment_level);
    println!("   State Hash: {}", resp.status.state_hash_blake3);
    Ok(())
}

pub async fn handle_service(
    client: &KillSwitchClient,
    action: Option<&str>,
) -> Result<()> {
    match action {
        None | Some("status") => {
            let status = client.get_service_status().await?;
            println!("\n================================================================================");
            println!("🔧 NATIVE SERVICE STATUS: {}", status.name);
            println!("================================================================================");
            println!("  Display Name: {}", status.display_name);
            println!("  State:        {}", status.state);
            println!("  Installed:    {}", status.is_installed);
            println!("  PID:          {:?}", status.pid);
            println!("  Binary Path:  {}", status.binary_path);
            println!("================================================================================\n");
        }
        Some(act) => {
            println!("🔧 Commanding service action: '{}'...", act);
            let resp = client.control_service(act).await?;
            println!("✅ Service Action Result: {}", resp.action);
            println!("   Service Name: {}", resp.service_name);
            println!("   New State:    {}", resp.resulting_status.state);
        }
    }
    Ok(())
}

pub async fn handle_lineage(
    client: &KillSwitchClient,
    action: &str,
    path_or_url: Option<&str>,
    sha256: Option<&str>,
    classification: Option<&str>,
    policy: Option<&str>,
    pid: Option<u32>,
) -> Result<()> {
    match action {
        "status" => {
            let status = client.get_lineage_status().await?;
            println!("\n================================================================================");
            println!("🧬 DLP OPENLINEAGE STATUS");
            println!("================================================================================");
            println!("  Total Processes Tracked:   {}", status.total_processes_tracked);
            println!("  Tainted Processes Count:   {}", status.tainted_processes_count);
            println!("  Total Sensitive Files:     {}", status.total_files_tracked);
            println!("  Tainted Files Count:       {}", status.tainted_files_count);
            println!("================================================================================\n");
        }
        "seed" => {
            let p = path_or_url.unwrap_or("C:\\confidential\\doc.docx");
            let s = sha256.unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
            let c = classification.unwrap_or("CrownJewel");
            let pol = policy.unwrap_or("Quarantine");

            let res = client.seed_lineage(p, s, c, pol).await?;
            println!("✅ Seeded Sensitive File: {}", res.path);
            println!("   Classification: {}", res.classification);
            println!("   Policy:         {}", res.policy);
        }
        "eval" => {
            let p = pid.unwrap_or(std::process::id());
            let dest = path_or_url.unwrap_or("https://external-exfil.com");

            let res = client.evaluate_lineage(p, dest).await?;
            println!("🔍 Egress Verdict for PID {}: {}", p, res.verdict);
            println!("   Is Blocked:      {}", res.is_block);
            if let Some(r) = res.reason {
                println!("   Reason:          {}", r);
            }
            if let Some(c) = res.classification {
                println!("   Classification:  {}", c);
            }
        }
        _ => anyhow::bail!("Unknown lineage subcommand: {}", action),
    }
    Ok(())
}

pub async fn handle_graph(
    client: &KillSwitchClient,
    action: &str,
    force_node: Option<&str>,
) -> Result<()> {
    match action {
        "state" => {
            let state = client.get_graph_state().await?;
            println!("\n================================================================================");
            println!("🕸️  LANGGRAPH ORCHESTRATOR STATE");
            println!("================================================================================");
            println!("  Incident ID:           {}", state.incident_id);
            println!("  Current Node:          {}", state.current_node);
            println!("  Mode:                  {}", state.mode);
            println!("  Aggregate Threat Score: {:.2}", state.aggregate_threat_score);
            println!("  Active Threats:        {}", state.active_threats_count);
            println!("  Execution Trace Len:   {}", state.execution_trace_len);
            println!("  Trace Chain Valid:     {}", state.trace_chain_valid);
            println!("================================================================================\n");
        }
        "step" => {
            let res = client.step_graph(force_node).await?;
            println!("✅ Graph Step Completed:");
            println!("   Executed Node: {}", res.executed_node);
            println!("   Next Node:     {}", res.next_node);
            println!("   Summary:       {}", res.summary);
            println!("   Threat Score:  {:.2}", res.threat_score);
            println!("   Is Isolated:   {}", res.is_isolated);
        }
        _ => anyhow::bail!("Unknown graph subcommand: {}", action),
    }
    Ok(())
}

pub async fn handle_verify() -> Result<()> {
    let report = SubsystemVerifier::run_all().await?;
    report.print_summary();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_research(
    client: &KillSwitchClient,
    action: &str,
    id: Option<&str>,
    title: Option<&str>,
    vector: Option<&str>,
    boundary: Option<&str>,
    quote: Option<&str>,
    crate_target: Option<&str>,
    operator: Option<&str>,
) -> Result<()> {
    match action {
        "list" | "status" | "menu" => {
            let menu = client.get_research_candidates().await?;
            let suite = killswitch_telemetry::run_paper2agent_accuracy_suite();
            println!("\n================================================================================");
            println!("🔬 KILLSWITCH ARXIV & LANGEXTRACT RESEARCH MENU (USER APPROVAL GATE + PAPER2AGENT)");
            println!("================================================================================");
            println!("  Mandatory User Approval:   {}", menu.user_approval_required);
            println!("  Pending Approval Count:    {}", menu.pending_count);
            println!("  Approved Count:            {}", menu.approved_count);
            println!("  Rejected Count:            {}", menu.rejected_count);
            println!("  Active Vectors in Code:    {}", menu.active_research_vectors_count);
            println!("  Enforced 2025-2026 Rules:  {}", menu.active_enforced_research_rules_count);
            println!("  Conformal Sources (K):     {}", menu.calibrated_sources_total);
            println!(
                "  Paper2Agent LLM Fusion:    {}/{} Rules Verified | TPR={:.1}% | FPR={:.1}% | Acc={:.1}%",
                suite.paper2agent_harnesses_passed,
                suite.total_rules_tested,
                suite.true_positive_rate_pct,
                suite.false_positive_rate_pct,
                suite.overall_accuracy_pct
            );
            println!("--------------------------------------------------------------------------------");
            for c in &menu.candidates {
                println!(
                    "  [{}] arXiv:{} (Rank {:.1} | Rel {:.1}% | Acc {:.1}%) — {}",
                    c.status, c.arxiv_id, c.rank_score, c.relevance_score, c.accuracy_score, c.title
                );
                println!(
                    "      ID: {} | Boundary: {} -> Crate: {}",
                    c.candidate_id, c.target_boundary, c.target_crate_enhancement
                );
                if c.has_code_repo && !c.code_repo_url.is_empty() {
                    println!("      📦 Verified Code Repo (+20pt): {}", c.code_repo_url);
                }
                println!("      Vector: {}", c.attack_vector);
                println!(
                    "      Grounded Quote [{}..{}]: \"{}\"",
                    c.source_char_start, c.source_char_end, c.source_quote
                );
                if let Some(seal) = &c.approval_seal_blake3 {
                    println!("      BLAKE3 Approval Seal: {}", seal);
                }
            }
            println!("================================================================================\n");
        }
        "verify-accuracy" | "accuracy" => {
            let suite = killswitch_telemetry::run_paper2agent_accuracy_suite();
            println!("\n================================================================================");
            println!("🎯 PAPER2AGENT & TRI-EVALUATOR LLM FUSION ACCURACY SUITE");
            println!("================================================================================");
            println!("  Status:            {}", suite.status);
            println!("  Rules Verified:    {}/{}", suite.paper2agent_harnesses_passed, suite.total_rules_tested);
            println!("  Aggregate TPR:     {:.1}%", suite.true_positive_rate_pct);
            println!("  Aggregate FPR:     {:.1}%", suite.false_positive_rate_pct);
            println!("  Accuracy Score:    {:.1}%", suite.overall_accuracy_pct);
            println!("  Byte-Exact AST:    {}", suite.byte_exact_parity);
            println!("  LLM Fusion Passed: {} ({} bp)", suite.llm_fusion_consensus_passed, suite.llm_fusion_confidence_bp);
            println!("================================================================================\n");
        }
        "discover" | "stage" => {
            let req = killswitch_server::types::ResearchDiscoverRequest {
                arxiv_id: id.map(|s| s.to_string()),
                query: id.map(|s| s.to_string()),
                title: title.map(|s| s.to_string()),
                attack_vector: vector.map(|s| s.to_string()),
                target_boundary: boundary.map(|s| s.to_string()),
                source_quote: quote.map(|s| s.to_string()),
                target_crate_enhancement: crate_target.map(|s| s.to_string()),
                code_repo_url: None,
                indicator_pattern: None,
            };
            let menu = client.discover_research_candidate(&req).await?;
            println!(
                "🔍 Staged candidate into Pending User Approval queue (Total Pending: {}). Run `killswitch --research-approve <ID>` to approve.",
                menu.pending_count
            );
        }
        "approve" | "reject" => {
            let target_id = id.unwrap_or("2603.02277");
            let req = killswitch_server::types::ResearchApproveRequest {
                candidate_id: target_id.to_string(),
                decision: action.to_string(),
                operator: Some(operator.unwrap_or("cli_operator").to_string()),
                arxiv_id: Some(target_id.to_string()),
                title: title.map(|s| s.to_string()),
                attack_vector: vector.map(|s| s.to_string()),
                target_boundary: boundary.map(|s| s.to_string()),
                source_quote: quote.map(|s| s.to_string()),
                target_crate_enhancement: crate_target.map(|s| s.to_string()),
                code_repo_url: None,
                indicator_pattern: None,
            };
            let res = client.approve_research_candidate(&req).await?;
            println!("{}", res.message);
            println!("   Candidate Status:       {}", res.candidate.status);
            println!("   Active Vectors in Code: {}", res.active_research_vectors_count);
            println!("   Enforced 2025-26 Rules: {}", res.active_enforced_research_rules_count);
            println!("   Conformal Sources (K):  {}", res.calibrated_sources_total);
            println!("   Live Probe Blocked:     {}", res.live_probe_verified);
            if let Some(seal) = res.candidate.approval_seal_blake3 {
                println!("   BLAKE3 Approval Seal:   {}", seal);
            }
        }
        _ => anyhow::bail!(
            "Unknown research action '{}'. Supported: list, verify-accuracy, discover, approve, reject",
            action
        ),
    }
    Ok(())
}

pub async fn handle_edr_behavior(action: &str) -> Result<()> {
    use killswitch_telemetry::{global_edr_behavioral_engine, EdrSensorTelemetryEvent};
    use killswitch_types::telemetry::TelemetryEventKind;

    let engine = global_edr_behavioral_engine();
    let act = action.to_ascii_lowercase();

    if act == "scan" || act == "status" {
        let _ = engine.collect_and_evaluate_live_host_snapshot();
    } else if act == "verify-chains" || act == "verify" {
        let lotl_cmd = ["powershell.exe", "-enc", "B64_DIAGNOSTIC_TEST_VECTOR"].join(" ");
        // 1. Office -> cmd -> encoded PowerShell -> unfamiliar external IP (LotL chain)
        let _ = engine.ingest_telemetry_event(&EdrSensorTelemetryEvent::new_process_create(
            24100,
            Some(1200),
            "WINWORD.EXE",
            "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
            "WINWORD.EXE Invoice.docm",
            "corp_user",
        ));
        let _ = engine.ingest_telemetry_event(&EdrSensorTelemetryEvent::new_process_create(
            24250,
            Some(24100),
            "cmd.exe",
            "C:\\Windows\\System32\\cmd.exe",
            &lotl_cmd,
            "corp_user",
        ));
        let mut ps_ev = EdrSensorTelemetryEvent::new_process_create(
            24310,
            Some(24250),
            "powershell.exe",
            "C:\\Windows\\System32\\powershell.exe",
            &lotl_cmd,
            "corp_user",
        );
        ps_ev.destination_ip = Some("198.51.100.42".to_string());
        ps_ev.destination_port = Some(8443);
        let _ = engine.ingest_telemetry_event(&ps_ev);

        // 2. Service account recon + temp unsigned DLL + 3-sigma outbound spike
        let recon_cmd = ["whoami", "net user"].join(" ");
        let _ = engine.ingest_telemetry_event(&EdrSensorTelemetryEvent::new_process_create(
            28100,
            Some(900),
            "cmd.exe",
            "C:\\Windows\\System32\\cmd.exe",
            &recon_cmd,
            "NT AUTHORITY\\NETWORK SERVICE",
        ));
        let mut dll_ev = EdrSensorTelemetryEvent::new_process_create(
            28120,
            Some(28100),
            "svc_worker.exe",
            "C:\\Program Files\\Service\\svc_worker.exe",
            "svc_worker.exe",
            "NT AUTHORITY\\NETWORK SERVICE",
        );
        dll_ev.event_kind = TelemetryEventKind::ImageLoadDll;
        dll_ev.target_file_or_dll_path =
            Some("C:\\Users\\Public\\AppData\\Local\\Temp\\unsigned_plugin.dll".to_string());
        dll_ev.module_is_signed = Some(false);
        let _ = engine.ingest_telemetry_event(&dll_ev);

        let mut exfil_ev = EdrSensorTelemetryEvent::new_process_create(
            28120,
            Some(28100),
            "svc_worker.exe",
            "C:\\Program Files\\Service\\svc_worker.exe",
            "svc_worker.exe --upload",
            "NT AUTHORITY\\NETWORK SERVICE",
        );
        exfil_ev.event_kind = TelemetryEventKind::NetworkConnect;
        exfil_ev.destination_ip = Some("203.0.113.88".to_string());
        exfil_ev.destination_port = Some(443);
        exfil_ev.outbound_bytes = 30_000_000;
        let _ = engine.ingest_telemetry_event(&exfil_ev);
    }

    let report = engine.status_report();
    println!("================================================================================");
    println!("🛡️  KILLSWITCH CONTINUOUS EDR BEHAVIORAL LINEAGE & BASELINE MONITOR");
    println!("================================================================================");
    println!(
        "  Tracked Process Lineage Nodes: {} | Learned Baseline Profiles: {} | Events Ingested: {}",
        report.tracked_processes_in_lineage_tree,
        report.learned_baseline_profiles,
        report.total_events_ingested
    );
    println!(
        "  MITRE IoA Hits: {} | Lineage Violations: {} | Baseline Deviations: {} | Auto-Containments: {}",
        report.total_ioa_matches,
        report.total_lineage_violations,
        report.total_baseline_deviations,
        report.automated_containments_triggered
    );
    println!("  Active Sensor Hooks: {}", report.active_sensor_hooks.join(" | "));
    println!("--------------------------------------------------------------------------------");
    for nar in &report.active_narratives {
        println!(
            "  • [{}] Risk={:.2} ({:?}) | Techniques={:?}",
            nar.narrative_id, nar.composite_risk_score, nar.severity, nar.mitre_techniques
        );
        println!("    Lineage: {}", nar.lineage_chain);
        println!("    Action:  {:?}", nar.containment_action);
        println!("    Seal:    {}", nar.blake3_narrative_seal);
    }
    println!("================================================================================");
    Ok(())
}


pub async fn handle_containment_suite() -> Result<()> {
    let oso_status = killswitch_telemetry::global_oso_aws_containment().status_report();
    let apc_status = killswitch_telemetry::global_apc_pdp().status_summary();
    let tamper_status = killswitch_telemetry::get_tamper_guard_status();
    let hitl_status = killswitch_telemetry::global_cognitive_redteam().get_status();

    println!("\n================================================================================");
    println!("🛡️  OSHOOSICLAW MIGRATED CONTAINMENT & KILLSWITCH SUITE");
    println!("================================================================================");
    println!(
        "  [1] Oso 3-Way Intersection + AWS R1-R5 Watchdog: Cluster='{}' | DesiredCount={} | Epoch={}",
        oso_status.cluster_name, oso_status.desired_count, oso_status.generation_epoch
    );
    println!(
        "  [2] Bounded Agents APC (arXiv:2608.15888):       Policy='{}' | CrossSessionLineage={} | EvidenceIntegrity={}",
        apc_status.active_policy_version,
        apc_status.enforce_cross_session_lineage,
        apc_status.evidence_chain_integrity_ok
    );
    println!(
        "  [3] 4-Gate DB & Executable Tamper Guard:         ConsoleHardened={} | ExeDaclHardened={} | MaintWindow={}",
        tamper_status.console_mode_hardened,
        tamper_status.exe_dacl_hardened,
        tamper_status.maintenance_window_active
    );
    println!(
        "  [4] Cognitive Red-Team HITL Interceptor:         Evaluations={} | AutoVetoes={} | Quorums={}",
        hitl_status.total_evaluations,
        hitl_status.total_auto_vetoes,
        hitl_status.total_quorum_completions
    );
    println!("================================================================================\n");
    Ok(())
}

pub async fn handle_cage(
    client: &KillSwitchClient,
    action: &str,
    spec: Option<&str>,
    tool: Option<&str>,
    amount: Option<f64>,
    trace: Option<&str>,
) -> Result<()> {
    match action {
        "status" => {
            let status = client.get_cage_status().await?;
            println!("\n================================================================================");
            println!("🛡️  GOOGLE CAGE GOVERNANCE KERNEL STATUS (arXiv:2606.12320)");
            println!("================================================================================");
            println!("  Kernel Status:            {}", if !status.llm_clients_in_kernel { "ACTIVE (Deterministic LLM-Free)" } else { "INACTIVE" });
            println!("  Active Substrate Digest:  {}", status.substrate_contract_digest);
            println!("  Active Contract ID:       {}", status.active_contract_id);
            println!("  Substrate Format:         {:?}", status.substrate_format);
            println!("  Total Evaluations:        {}", status.total_evaluations);
            println!("  Clear Verdicts:           {}", status.total_cleared);
            println!("  Refusal Verdicts:         {}", status.total_refused);
            println!("  Cumulative Fiscal Spend:  ${:.2} / ${:.2}", status.fiscal_spent_usd, status.fiscal_cap_usd);
            println!("  Receipts in Evidence Log: {}", status.evidence_receipt_count);
            println!("================================================================================\n");
        }
        "verify" => {
            let report = SubsystemVerifier::verify_cage_governance().await?;
            println!("\n================================================================================");
            println!("🛡️  CAGE GOVERNANCE SELF-DIAGNOSTIC VERIFICATION");
            println!("================================================================================");
            println!("  Status:       {}", if report.passed { "PASS" } else { "FAIL" });
            println!("  Details:      {}", report.details);
            println!("  Duration:     {} ms", report.duration_ms);
            println!("================================================================================\n");
        }
        "compile" => {
            let spec_content = if let Some(s) = spec {
                if std::path::Path::new(s).exists() {
                    std::fs::read_to_string(s)?
                } else {
                    s.to_string()
                }
            } else {
                bail!("Missing --spec parameter with path or specification string");
            };
            let artifact = killswitch_telemetry::SubstrateCompiler::detect_and_compile_str(&spec_content)
                .map_err(|e| anyhow::anyhow!("Compilation failed: {}", e))?;
            println!("\n================================================================================");
            println!("🛡️  COMPILED CAGE SUBSTRATE CONTRACT");
            println!("================================================================================");
            println!("  Contract ID:     {}", artifact.contract_id);
            println!("  Detected Format: {:?}", artifact.format);
            println!("  SHA-256 Digest:  {}", artifact.substrate_contract_digest);
            println!("  Allowed Tools:   {:?}", artifact.allowed_tools);
            println!("  Max Transfer:    ${:.2}", artifact.max_single_transfer_usd);
            println!("  Fiscal Cap:      ${:.2}", artifact.fiscal_cap_usd);
            println!("  Digest Verified: {}", artifact.verify_digest());
            println!("================================================================================\n");
        }
        "evaluate" => {
            let tool_name = tool.unwrap_or("execute_trade");
            let req = killswitch_telemetry::CageEvaluationRequest {
                agent_id: "cli_operator".to_string(),
                role: "containment_orchestrator".to_string(),
                tool_name: tool_name.to_string(),
                arguments: serde_json::json!({ "amount": amount.unwrap_or(100.0) }),
                confidence_score: Some(0.95),
                amount_usd: amount,
                dose_mg: None,
                warrant_token: None,
                human_approval: None,
                context: None,
            };
            let resp = client.evaluate_cage(&req).await?;
            println!("\n================================================================================");
            println!("🛡️  CAGE POLICY ENFORCEMENT POINT EVALUATION");
            println!("================================================================================");
            println!("  Verdict:        {:?}", resp.verdict);
            println!("  Tier:           {:?}", resp.tier);
            println!("  Rule ID:        {}", resp.rule_id);
            println!("  Details:        {}", resp.error_message.as_deref().unwrap_or("Action cleared all 8 tiers"));
            println!("  Receipt Digest: {}", resp.receipt.decision_digest);
            println!("================================================================================\n");
        }
        "verify-trace" => {
            let trace_content = if let Some(t) = trace {
                if std::path::Path::new(t).exists() {
                    std::fs::read_to_string(t)?
                } else {
                    t.to_string()
                }
            } else {
                bail!("Missing --trace parameter with file path or JSON array");
            };
            let events: Vec<killswitch_telemetry::GovernanceTraceEvent> = serde_json::from_str(&trace_content)?;
            let report = client.verify_cage_trace(&events).await?;
            println!("\n================================================================================");
            println!("🛡️  CAGE TRACE MODEL CONFORMANCE REPORT");
            println!("================================================================================");
            println!("  Conformant:     {}", report.is_conformant);
            println!("  Events:         {}", report.total_events);
            println!("  Violations:     {:?}", report.violations);
            println!("================================================================================\n");
        }
        other => bail!("Unknown CAGE action '{}'. Use status, verify, compile, evaluate, or verify-trace.", other),
    }
    Ok(())
}

