//! # CLI Command Handlers & Formatters

use anyhow::Result;
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
