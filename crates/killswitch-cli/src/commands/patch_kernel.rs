//! # OS Kernel Vulnerability Scanning & Native Patch Orchestration CLI Handler

use anyhow::Result;
use killswitch_kernel_patcher::{
    is_elevated, HostKernelInfo, KernelPatcher, PatcherError, ScanOptions,
};

/// Handles the `killswitch patch-kernel` CLI subcommand.
///
/// Discovers the running OS kernel, queries the NVD API 2.0 for matching CVEs / CISA KEV entries,
/// formats structured findings, and optionally invokes OS-native kernel patch workflows.
///
/// # Secret Hygiene Invariant
/// `NVD_API_KEY` is NEVER accepted as a CLI parameter (preventing OS process-table leaks).
/// It is read strictly from `std::env::var("NVD_API_KEY")`.
pub async fn handle_patch_kernel(
    dry_run: bool,
    kev_only: bool,
    min_cvss: Option<f32>,
    cpe: Option<String>,
    apply: bool,
) -> Result<()> {
    // 1. Host Kernel Discovery
    let host_info = match HostKernelInfo::detect_host_kernel() {
        Ok(info) => info,
        Err(e) => {
            eprintln!("❌ Host kernel detection failed: {}", e);
            return Err(e.into());
        }
    };

    let target_cpe = cpe.unwrap_or_else(|| host_info.cpe23.clone());
    let has_env_key = std::env::var("NVD_API_KEY").is_ok();

    println!("\n================================================================================");
    println!("🛡️  HOST KERNEL DISCOVERY & NVD VULNERABILITY SCANNER");
    println!("================================================================================");
    println!("  OS Family:        {}", host_info.os_family);
    println!("  OS Version:       {}", host_info.os_version);
    println!("  Kernel Release:   {}", host_info.kernel_release);
    println!("  Architecture:     {}", host_info.architecture);
    println!("  Target CPE 2.3:   {}", target_cpe);
    println!(
        "  NVD API Key:      {}",
        if has_env_key {
            "Configured via NVD_API_KEY environment variable"
        } else {
            "None (public rate-limited mode)"
        }
    );
    if kev_only {
        println!("  Filter Mode:      CISA KEV Only");
    }
    if let Some(cvss) = min_cvss {
        println!("  Min CVSS Score:   {:.1}", cvss);
    }
    println!("================================================================================\n");

    // 2. Vulnerability Scan against NVD API 2.0
    println!(
        "🔍 Querying NVD API 2.0 for kernel vulnerabilities affecting '{}'...",
        target_cpe
    );

    let options = ScanOptions {
        cpe: Some(target_cpe.clone()),
        min_cvss_score: min_cvss,
        kev_only,
        api_key: std::env::var("NVD_API_KEY").ok(),
        timeout_secs: 30,
    };

    let patcher = KernelPatcher::new();
    match patcher.scan_kernel_vulnerabilities(&options).await {
        Ok(vulns) => {
            if vulns.is_empty() {
                println!("✅ Zero vulnerabilities found matching the specified criteria.");
            } else {
                let kev_count = vulns.iter().filter(|v| v.is_cisa_kev).count();
                println!(
                    "\n⚠️  Found {} vulnerabilities affecting target kernel ({} CISA KEV):\n",
                    vulns.len(),
                    kev_count
                );
                for v in &vulns {
                    println!("--------------------------------------------------------------------------------");
                    let score_str = match v.cvss_v31_score {
                        Some(score) => format!("{:.1}", score),
                        None => "N/A".to_string(),
                    };
                    let sev_str = v.cvss_v31_severity.as_deref().unwrap_or("UNKNOWN");

                    if v.is_cisa_kev {
                        println!(
                            "🚨 [CISA KEV] {} | CVSS v3.1: {} ({})",
                            v.cve_id, score_str, sev_str
                        );
                        if let Some(ref name) = v.cisa_vulnerability_name {
                            println!("   Vulnerability Name: {}", name);
                        }
                        if let Some(ref added) = v.cisa_exploit_add {
                            println!("   Added to KEV:       {}", added);
                        }
                        if let Some(ref due) = v.cisa_action_due {
                            println!("   Remediation Due:    {}", due);
                        }
                        if let Some(ref action) = v.cisa_required_action {
                            println!("   Required Action:    {}", action);
                        }
                    } else {
                        println!("⚠️  {} | CVSS v3.1: {} ({})", v.cve_id, score_str, sev_str);
                    }
                    if !v.description.is_empty() {
                        println!("   Description:        {}", v.description);
                    }
                }
                println!("--------------------------------------------------------------------------------\n");
            }
        }
        Err(PatcherError::RateLimited) => {
            eprintln!("⚠️  Rate limited by NIST NVD API 2.0. Set the NVD_API_KEY environment variable to increase NIST rate limits.");
        }
        Err(e) => {
            eprintln!("⚠️  NVD vulnerability scan query notice: {}", e);
        }
    }

    // 3. Patch Orchestration
    let should_patch = apply || dry_run;
    if should_patch {
        let is_dry_run = dry_run || !apply;
        println!("🔧 Orchestrating native OS kernel patch workflow...");
        if is_dry_run {
            println!("   [DRY-RUN SIMULATION - No kernel or OS changes will be applied]");
        } else if !is_elevated() {
            eprintln!("❌ Insufficient privileges: OS-native kernel patch execution requires Administrator/root privileges.");
            return Err(PatcherError::InsufficientPrivileges.into());
        }

        let exec_result = patcher.apply_os_kernel_patch(is_dry_run).await?;
        println!(
            "\n================================================================================"
        );
        println!("🛡️  NATIVE KERNEL PATCH ORCHESTRATION RESULT");
        println!(
            "================================================================================"
        );
        println!("  Target Subsystem: {}", exec_result.os_subsystem);
        println!(
            "  Mode:             {}",
            if exec_result.dry_run {
                "Dry-Run Simulation"
            } else {
                "Live Execution"
            }
        );
        println!(
            "  Command:          {} {}",
            exec_result.command,
            exec_result.args.join(" ")
        );
        println!("  Success:          {}", exec_result.success);
        println!("  Output:\n{}", exec_result.output);
        println!(
            "================================================================================\n"
        );
    } else {
        println!("💡 Tip: Pass '--apply --dry-run' (or '--dry-run') to preview OS-native patch command, or '--apply' with elevated privileges to execute.\n");
    }

    Ok(())
}
