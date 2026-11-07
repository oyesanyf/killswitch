//! CLI handler for `killswitch agentsonar` subcommands.
//!
//! Provides dynamic runtime management of SQLite WAL AI-agent rules (`agents`),
//! noise domains (`ignore`), browser process substrings (`browsers`), heuristic
//! SSE traffic-shape weights (`heuristics`), interactive flow triage (`triage`),
//! JSONL stdin/stdout external classification (`classify`), JSON rule `export`/`import`,
//! `osquery` Auto Table Construction schema generation (`osquery-schema`), and live
//! flow monitoring (`monitor` / `status`).

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use killswitch_telemetry::agentsonar::{
    default_agentsonar_db_path, generate_osquery_atc_schema, resolve_safe_db_path,
    AgentSonarEngine, DynamicRuleSet, HeuristicWeightsPatch, TriageDecision,
};

#[derive(Args, Debug, Clone)]
pub struct AgentSonarCliArgs {
    /// Network interface hint for live monitoring ("any" for all interfaces)
    #[arg(short, long, default_value = "any")]
    pub interface: String,

    /// Include traffic without local process association (PID 0)
    #[arg(long, default_value_t = false)]
    pub enable_pid0: bool,

    /// Output all domains including noise-suppressed domains
    #[arg(short, long, default_value_t = false)]
    pub all: bool,

    /// Path to local SQLite WAL persistence and dynamic rule database
    #[arg(long)]
    pub db_path: Option<String>,

    /// Optional hot-reloadable JSON rule seed/override path
    #[arg(long)]
    pub config_path: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<AgentSonarCommands>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum AgentSonarCommands {
    /// Display current Dynamic AgentSonar SQLite WAL & rule engine status
    Status,

    /// Classify JSONL events from stdin using dynamic SQLite rules and optional external classifier
    Classify {
        /// Optional external classifier command to pipe events through (AST-validated, 2s timeout)
        #[arg(short, long)]
        external_cmd: Option<String>,
    },

    /// Dynamically manage known AI agent process-to-domain wildcard rules
    Agents {
        #[command(subcommand)]
        action: AgentRuleAction,
    },

    /// Dynamically manage ignored noise domains
    Ignore {
        #[command(subcommand)]
        action: IgnoreDomainAction,
    },

    /// Dynamically manage non-programmatic interactive browser process substrings
    Browsers {
        #[command(subcommand)]
        action: BrowserProcAction,
    },

    /// Dynamically update heuristic SSE traffic-shape classifier weights and thresholds at runtime
    Heuristics {
        #[arg(long)]
        min_byte_ratio: Option<f64>,
        #[arg(long)]
        max_byte_ratio: Option<f64>,
        #[arg(long)]
        weight_byte_asymmetry: Option<f64>,
        #[arg(long)]
        min_pkt_ratio: Option<f64>,
        #[arg(long)]
        min_avg_pkt_in: Option<f64>,
        #[arg(long)]
        max_avg_pkt_in: Option<f64>,
        #[arg(long)]
        weight_pkt_streaming: Option<f64>,
        #[arg(long)]
        min_duration_ms: Option<u64>,
        #[arg(long)]
        max_duration_ms: Option<u64>,
        #[arg(long)]
        weight_duration: Option<f64>,
        #[arg(long)]
        weight_programmatic: Option<f64>,
    },

    /// Triage unknown, high-scoring Shadow AI traffic flows
    Triage {
        /// Minimum AI score threshold in [0.0, 1.0]
        #[arg(long, default_value_t = 0.50)]
        min_score: f64,

        /// Emit candidates as JSON without prompting stdin
        #[arg(long, default_value_t = false)]
        non_interactive: bool,
    },

    /// Export all dynamic rules, noise domains, browser filters, and heuristics to JSON
    Export,

    /// Import dynamic rules and heuristics from a JSON file
    Import {
        #[arg(long)]
        file: String,
    },

    /// Generate the osquery Auto Table Construction (ATC) configuration for all 5 dynamic tables
    OsquerySchema,

    /// Sample live OS network flows continuously (or for N bounded cycles) into SQLite WAL
    Monitor {
        /// Optional bounded number of 3-second collection cycles before exiting
        #[arg(long)]
        cycles: Option<usize>,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum AgentRuleAction {
    List,
    Add {
        #[arg(long)]
        agent: String,
        #[arg(long)]
        proc_pattern: String,
        #[arg(long)]
        domain_pattern: String,
    },
    Remove {
        #[arg(long)]
        agent: String,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum IgnoreDomainAction {
    List,
    Add { domain: String },
    Remove { domain: String },
}

#[derive(Subcommand, Debug, Clone)]
pub enum BrowserProcAction {
    List,
    Add { proc_substring: String },
    Remove { proc_substring: String },
}

pub fn handle_agentsonar(args: AgentSonarCliArgs) -> Result<()> {
    let db_path = match &args.db_path {
        Some(raw) => resolve_safe_db_path(raw)?,
        None => default_agentsonar_db_path(),
    };
    let cfg_path = args.config_path.clone().or_else(|| {
        let default_cfg = PathBuf::from("config").join("agentsonar.json");
        if args.db_path.is_none() && default_cfg.exists() {
            Some(default_cfg)
        } else {
            None
        }
    });

    let engine = Arc::new(AgentSonarEngine::new(db_path.clone(), cfg_path)?);

    match args.command.unwrap_or(AgentSonarCommands::Status) {
        AgentSonarCommands::Status => {
            let status = engine.status_report()?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        AgentSonarCommands::OsquerySchema => {
            let schema = generate_osquery_atc_schema(&db_path.to_string_lossy());
            println!("{}", serde_json::to_string_pretty(&schema)?);
        }
        AgentSonarCommands::Export => {
            let rules = engine.load_rules()?;
            println!("{}", serde_json::to_string_pretty(&rules)?);
        }
        AgentSonarCommands::Import { file } => {
            let safe_file = resolve_safe_db_path(&file)?;
            let data = fs::read_to_string(&safe_file)
                .with_context(|| format!("Failed to read import file {}", safe_file.display()))?;
            let imported: DynamicRuleSet =
                serde_json::from_str(&data).context("Invalid AgentSonar rule JSON")?;
            engine.import_ruleset(&imported)?;
            println!(
                "Dynamically imported {} agent rules, {} noise domains, and updated heuristics.",
                imported.agents.len(),
                imported.noise_domains.len()
            );
        }
        AgentSonarCommands::Agents { action } => match action {
            AgentRuleAction::List => {
                let rules = engine.load_rules()?;
                println!("{:<22} {:<24} DOMAIN PATTERN", "AGENT", "PROCESS PATTERN");
                for a in rules.agents {
                    println!(
                        "{:<22} {:<24} {}",
                        a.agent, a.proc_pattern, a.domain_pattern
                    );
                }
            }
            AgentRuleAction::Add {
                agent,
                proc_pattern,
                domain_pattern,
            } => {
                engine.add_agent_rule(&agent, &proc_pattern, &domain_pattern)?;
                println!(
                    "Added dynamic rule: {} -> (proc: {}, domain: {})",
                    agent, proc_pattern, domain_pattern
                );
            }
            AgentRuleAction::Remove { agent } => {
                let removed = engine.remove_agent_rule(&agent)?;
                println!("Removed {} rule(s) for agent: {}", removed, agent);
            }
        },
        AgentSonarCommands::Ignore { action } => match action {
            IgnoreDomainAction::List => {
                let rules = engine.load_rules()?;
                let mut sorted: Vec<String> = rules.noise_domains.into_iter().collect();
                sorted.sort();
                for d in sorted {
                    println!("{}", d);
                }
            }
            IgnoreDomainAction::Add { domain } => {
                engine.add_noise_domain(&domain)?;
                println!("Added noise domain: {}", domain.to_ascii_lowercase());
            }
            IgnoreDomainAction::Remove { domain } => {
                let removed = engine.remove_noise_domain(&domain)?;
                println!(
                    "Removed noise domain: {} ({} entry removed)",
                    domain.to_ascii_lowercase(),
                    removed
                );
            }
        },
        AgentSonarCommands::Browsers { action } => match action {
            BrowserProcAction::List => {
                let rules = engine.load_rules()?;
                for b in rules.non_programmatic_procs {
                    println!("{}", b);
                }
            }
            BrowserProcAction::Add { proc_substring } => {
                engine.add_browser_proc(&proc_substring)?;
                println!(
                    "Added browser process filter: {}",
                    proc_substring.to_ascii_lowercase()
                );
            }
            BrowserProcAction::Remove { proc_substring } => {
                let removed = engine.remove_browser_proc(&proc_substring)?;
                println!(
                    "Removed browser process filter: {} ({} entry removed)",
                    proc_substring.to_ascii_lowercase(),
                    removed
                );
            }
        },
        AgentSonarCommands::Heuristics {
            min_byte_ratio,
            max_byte_ratio,
            weight_byte_asymmetry,
            min_pkt_ratio,
            min_avg_pkt_in,
            max_avg_pkt_in,
            weight_pkt_streaming,
            min_duration_ms,
            max_duration_ms,
            weight_duration,
            weight_programmatic,
        } => {
            let patch = HeuristicWeightsPatch {
                min_byte_ratio,
                max_byte_ratio,
                weight_byte_asymmetry,
                min_pkt_ratio,
                min_avg_pkt_in,
                max_avg_pkt_in,
                weight_pkt_streaming,
                min_duration_ms,
                max_duration_ms,
                weight_duration,
                weight_programmatic,
            };
            let updated = engine.update_heuristics(&patch)?;
            println!(
                "Updated heuristic weights:\n{}",
                serde_json::to_string_pretty(&updated)?
            );
        }
        AgentSonarCommands::Triage {
            min_score,
            non_interactive,
        } => {
            let candidates = engine.triage_candidates(min_score)?;
            if non_interactive {
                println!("{}", serde_json::to_string_pretty(&candidates)?);
                return Ok(());
            }
            if candidates.is_empty() {
                println!(
                    "No unclassified high-scoring flows found (min_score = {:.2}).",
                    min_score
                );
                return Ok(());
            }

            let stdin = io::stdin();
            let mut lines = stdin.lock().lines();
            for cand in candidates {
                println!("\n--- UNKNOWN HIGH-SCORING FLOW ---");
                println!(
                    "Process:  {}\nDomain:   {}\nAI Score: {:.2}\nTraffic:  in={}B out={}B pkts_in={} dur={}ms",
                    cand.proc_name,
                    cand.domain,
                    cand.ai_score,
                    cand.bytes_in,
                    cand.bytes_out,
                    cand.packets_in,
                    cand.duration_ms
                );
                print!("Action: [k]nown agent, [n]oise/ignore, [s]kip, [q]uit > ");
                io::stdout().flush()?;

                let Some(Ok(choice)) = lines.next() else {
                    break;
                };
                match choice.trim().to_ascii_lowercase().as_str() {
                    "k" => {
                        print!("Enter agent name (e.g. my-custom-agent): ");
                        io::stdout().flush()?;
                        if let Some(Ok(agent_name)) = lines.next() {
                            let agent_name = agent_name.trim();
                            if !agent_name.is_empty() {
                                engine.apply_triage_decision(&TriageDecision::KnownAgent {
                                    agent: agent_name.to_string(),
                                    proc_pattern: cand.proc_name.clone(),
                                    domain_pattern: cand.domain.clone(),
                                })?;
                                println!(
                                    "Saved rule for '{}' and updated historical events.",
                                    agent_name
                                );
                            }
                        }
                    }
                    "n" => {
                        engine.apply_triage_decision(&TriageDecision::IgnoreNoise {
                            domain: cand.domain.clone(),
                        })?;
                        println!(
                            "Added '{}' to noise list and muted historical events.",
                            cand.domain
                        );
                    }
                    "q" => break,
                    _ => println!("Skipped."),
                }
            }
        }
        AgentSonarCommands::Classify { external_cmd } => {
            let stdin = io::stdin();
            for line in stdin.lock().lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let out = engine.classify_jsonl_line(&line, external_cmd.as_deref())?;
                println!("{}", serde_json::to_string(&out)?);
            }
        }
        AgentSonarCommands::Monitor { cycles } => {
            let max_cycles = cycles.unwrap_or(usize::MAX);
            for idx in 0..max_cycles {
                let flushed = engine.sample_live_host_flows_once(args.all)?;
                let recent = engine.list_events(25)?;
                for ev in recent {
                    if args.all || ev.ai_score > 0.0 || !ev.agent.is_empty() {
                        println!("{}", serde_json::to_string(&ev)?);
                    }
                }
                if idx + 1 < max_cycles {
                    std::thread::sleep(Duration::from_secs(3));
                } else if cycles.is_some() {
                    eprintln!(
                        "Completed {} AgentSonar monitor cycle(s) ({} flows flushed).",
                        max_cycles, flushed
                    );
                }
            }
        }
    }

    Ok(())
}
