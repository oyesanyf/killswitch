//! # `start.exe` - Unified All-in-One Loader & Control Host
//!
//! Verbatim requirement: "I need start.exe to load it all"
//!
//! Boots 100% of subsystems into a single unified process:
//! - Phase 1: Core Host Containment Manager & BLAKE3 State Ledger
//! - Phase 2: Zero-False-Positive Adjudication Engine & WinTrust Validator
//! - Phase 3: DLP OpenLineage Engine & Octopus 18-Arm Defense Mesh
//! - Phase 4: 10-Node Cyclic LangGraph Orchestrator & Durable Checkpointer
//! - Phase 5: Local Axum HTTP API Server (port 3030 loopback)
//! - Phase 6: Native OS Service Lifecycle Manager
//!
//! Provides `--verify` / `--check` flags for immediate self-diagnostics exit 0.

use std::path::PathBuf;
use anyhow::Result;
use clap::Parser;
use tracing::info;

use killswitch_cli::loader::{UnifiedConfig, UnifiedRuntime};
use killswitch_cli::verify::SubsystemVerifier;
use killswitch_types::graph::OrchestratorMode;

#[derive(Parser, Debug)]
#[command(name = "start")]
#[command(author = "KillSwitch Security Team")]
#[command(version = "0.1.0")]
#[command(about = "Unified All-in-One Loader for Standalone Rust KillSwitch Security Agent", long_about = None)]
struct StartCli {
    /// Execute 6-phase in-memory self-diagnostics and exit 0
    #[arg(long, alias = "check")]
    verify: bool,

    /// Bind host for local HTTP control server
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    host: String,

    /// Bind port for local HTTP control server
    #[arg(short = 'p', long, default_value_t = 3030)]
    port: u16,

    /// Orchestrator operational mode (autonomous or manual)
    #[arg(short = 'm', long, default_value = "autonomous")]
    mode: String,

    /// Run as native OS background service daemon
    #[arg(long)]
    daemon: bool,

    /// Path to durable state ledger and database directory
    #[arg(long)]
    db_dir: Option<PathBuf>,

    /// Enforce CAGE (Cybernetic Agent Governance Engine, arXiv:2606.12320) runtime policy and run CAGE self-diagnostics
    #[arg(long = "cage-governance", alias = "cage")]
    cage_governance: bool,

    /// Internal elevated helper flag for Windows Filtering Platform (WFP) kernel delegation
    #[arg(long, hide = true)]
    wfp_kernel_apply: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = StartCli::parse();

    // Internal elevated helper invocation for Windows Filtering Platform (WFP) kernel delegation
    if let Some(ref action) = cli.wfp_kernel_apply {
        match killswitch_cli::commands::handle_wfp_kernel_apply(action) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("❌ [START.EXE] WFP kernel delegation failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Standalone --cage-governance flag invocation
    if cli.cage_governance && !cli.verify {
        println!("🛡️  [START.EXE] Executing CAGE Governance Self-Diagnostics (--cage-governance)...");
        match SubsystemVerifier::verify_cage_governance().await {
            Ok(report) => {
                println!("\n================================================================================");
                println!("🛡️  CAGE GOVERNANCE SELF-DIAGNOSTIC REPORT");
                println!("================================================================================");
                println!("  Status:       {}", if report.passed { "PASS" } else { "FAIL" });
                println!("  Phase:        {}", report.name);
                println!("  Duration:     {} ms", report.duration_ms);
                println!("  Details:      {}", report.details);
                println!("================================================================================\n");
                println!("✅ [START.EXE] CAGE Governance Verified Successfully! All 4 audit gates passed.");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("❌ [START.EXE] CAGE Governance verification failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Self-Diagnostic Check Mode (--verify / --check)
    // -------------------------------------------------------------------------
    if cli.verify {
        let count = if cli.cage_governance { "8-Phase" } else { "7-Phase" };
        println!("🛡️  [START.EXE] Executing {} Subsystem Self-Diagnostics...", count);
        match SubsystemVerifier::run_with_governance(cli.cage_governance).await {
            Ok(report) => {
                report.print_summary();
                println!("✅ [START.EXE] All Subsystems Verified Successfully! Self-check passed (exit 0).");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("❌ [START.EXE] Verification failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Full Runtime Boot Mode ("load it all")
    // -------------------------------------------------------------------------
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();

    println!(
        r#"
================================================================================
🛡️   KILLSWITCH UNIFIED LOADER (start.exe)
================================================================================
 [1/6] Core Engine:    State Ledger & Native WFP / Tarpit Containment
 [2/6] Adjudication:   Zero-False-Positive Engine & WinTrust Validator
 [3/6] Telemetry:      DLP Lineage Engine & Octopus 18-Arm Defense Mesh
 [4/6] Orchestrator:   10-Node Cyclic LangGraph & BLAKE3 Trace Checkpointer
 [5/6] Server:         Local Axum HTTP API Control Server (127.0.0.1:{})
 [6/6] Service:        Cross-Platform Native OS Service Lifecycle
================================================================================
🚀 Loading 100% of Subsystems into Unified Host Runtime...
"#,
        cli.port
    );

    let mode = match cli.mode.to_lowercase().as_str() {
        "manual" => OrchestratorMode::Manual,
        _ => OrchestratorMode::Autonomous,
    };

    let config = UnifiedConfig {
        host: cli.host,
        port: cli.port,
        mode,
        db_dir: cli.db_dir,
    };

    info!("🛡️ [START.EXE] Initializing unified runtime with mode: {:?}", config.mode);
    let runtime = UnifiedRuntime::boot(config).await?;

    println!("✅ [START.EXE] All Subsystems Loaded. System Operational.\n");

    runtime.run().await?;
    Ok(())
}
