//! # `killswitch.exe` - Unified All-in-One Loader, WebUI Host & Operator CLI
//!
//! When invoked with no subcommand (e.g., `killswitch.exe` or `killswitch.exe -p 4040`),
//! boots 100% of the 6 KillSwitch subsystems into a single unified runtime and serves
//! the Interactive WebUI Dashboard + Local Control API (with automatic port fallback if 3030 is in use).
//!
//! Also provides all operator subcommands (`status`, `isolate`, `restore`, `service`, `lineage`, `graph`, `verify`).

use std::path::PathBuf;
use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;

use killswitch_cli::client::KillSwitchClient;
use killswitch_cli::commands::*;
use killswitch_cli::loader::{UnifiedConfig, UnifiedRuntime};
use killswitch_cli::verify::SubsystemVerifier;
use killswitch_types::graph::OrchestratorMode;

#[derive(Parser, Debug)]
#[command(name = "killswitch")]
#[command(author = "KillSwitch Security Team")]
#[command(version = "0.1.0")]
#[command(about = "Standalone Rust KillSwitch Security Agent, WebUI Dashboard & Unified Loader", long_about = None)]
struct Cli {
    /// Execute 6-phase in-memory self-diagnostics and exit 0
    #[arg(long, alias = "check")]
    verify: bool,

    /// Local HTTP & WebUI control server host
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    host: String,

    /// Local HTTP & WebUI control server port (automatically tries fallback ports if in use)
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

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Boot the full 6-phase runtime and launch the Interactive WebUI Dashboard (default when no subcommand is given)
    #[command(visible_alias = "start", visible_alias = "serve", visible_alias = "ui")]
    Run,

    /// Query operational containment and security agent status
    Status,

    /// Engage emergency endpoint isolation and network containment
    Isolate {
        #[arg(short, long, default_value = "admin_operator")]
        operator: String,

        #[arg(short, long, default_value = "Manual containment requested")]
        reason: String,

        #[arg(short, long)]
        level: Option<String>,

        #[arg(short, long)]
        token: Option<String>,
    },

    /// Disarm containment and restore network connectivity
    Restore {
        #[arg(short, long, default_value = "admin_operator")]
        operator: String,

        #[arg(short, long, default_value = "Threat neutralized; operator restore")]
        reason: String,

        #[arg(short, long)]
        token: Option<String>,
    },

    /// Inspect or control the native OS background service
    Service {
        #[arg(default_value = "status")]
        action: String,
    },

    /// Inspect and evaluate DLP OpenLineage data provenance
    Lineage {
        #[arg(default_value = "status")]
        action: String,

        #[arg(short, long)]
        path: Option<String>,

        #[arg(short, long)]
        sha256: Option<String>,

        #[arg(short, long)]
        classification: Option<String>,

        #[arg(long)]
        policy: Option<String>,

        #[arg(long)]
        pid: Option<u32>,

        #[arg(long)]
        url: Option<String>,
    },

    /// Inspect or step the 10-node cyclic LangGraph orchestrator
    Graph {
        #[arg(default_value = "state")]
        action: String,

        #[arg(long)]
        node: Option<String>,
    },

    /// Run the 6-phase in-memory self-diagnostics
    Verify,
}

async fn boot_unified_webui_runtime(
    host: String,
    port: u16,
    mode_str: String,
    db_dir: Option<PathBuf>,
) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .try_init()
        .ok();

    println!(
        r#"
================================================================================
🛡️   KILLSWITCH UNIFIED LOADER & WEBUI HOST (killswitch.exe)
================================================================================
 [1/6] Core Engine:    State Ledger & Native WFP / Tarpit Containment
 [2/6] Adjudication:   Zero-False-Positive Engine & WinTrust Validator
 [3/6] Telemetry:      DLP Lineage Engine & Octopus 18-Arm Defense Mesh
 [4/6] Orchestrator:   10-Node Cyclic LangGraph & BLAKE3 Trace Checkpointer
 [5/6] WebUI & Server: Local Axum Control API & Interactive WebUI ({}:{})
 [6/6] Service:        Cross-Platform Native OS Service Lifecycle
================================================================================
🚀 Loading 100% of Subsystems into Unified Host Runtime...
"#,
        host, port
    );

    let mode = match mode_str.to_lowercase().as_str() {
        "manual" => OrchestratorMode::Manual,
        _ => OrchestratorMode::Autonomous,
    };

    let config = UnifiedConfig {
        host,
        port,
        mode,
        db_dir,
    };

    info!(
        "🛡️ [KILLSWITCH.EXE] Initializing unified runtime with mode: {:?}",
        config.mode
    );
    let runtime = UnifiedRuntime::boot(config).await?;

    println!("✅ [KILLSWITCH.EXE] All Subsystems Loaded. System Operational.\n");

    runtime.run().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.verify {
        println!("🛡️  [KILLSWITCH.EXE] Executing 7-Phase Subsystem Self-Diagnostics...");
        match SubsystemVerifier::run_all().await {
            Ok(report) => {
                report.print_summary();
                println!("✅ [KILLSWITCH.EXE] All 7 Subsystems Verified Successfully! Self-check passed (exit 0).");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("❌ [KILLSWITCH.EXE] Verification failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    let client = KillSwitchClient::new(&cli.host, cli.port);

    match cli.command {
        None | Some(Commands::Run) => {
            boot_unified_webui_runtime(cli.host, cli.port, cli.mode, cli.db_dir).await?;
        }
        Some(Commands::Status) => handle_status(&client).await?,
        Some(Commands::Isolate {
            operator,
            reason,
            level,
            token,
        }) => {
            handle_isolate(
                &client,
                &operator,
                &reason,
                level.as_deref(),
                token.as_deref(),
            )
            .await?
        }
        Some(Commands::Restore {
            operator,
            reason,
            token,
        }) => handle_restore(&client, &operator, &reason, token.as_deref()).await?,
        Some(Commands::Service { action }) => handle_service(&client, Some(&action)).await?,
        Some(Commands::Lineage {
            action,
            path,
            sha256,
            classification,
            policy,
            pid,
            url,
        }) => {
            let path_or_url = url.as_deref().or(path.as_deref());
            handle_lineage(
                &client,
                &action,
                path_or_url,
                sha256.as_deref(),
                classification.as_deref(),
                policy.as_deref(),
                pid,
            )
            .await?
        }
        Some(Commands::Graph { action, node }) => {
            handle_graph(&client, &action, node.as_deref()).await?
        }
        Some(Commands::Verify) => handle_verify().await?,
    }

    Ok(())
}
