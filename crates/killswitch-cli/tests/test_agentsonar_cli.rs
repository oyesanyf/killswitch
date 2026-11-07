//! Integration tests for `killswitch agentsonar` CLI handler (`agentsonar_cli.rs`).

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use killswitch_cli::agentsonar_cli::{
    handle_agentsonar, AgentRuleAction, AgentSonarCliArgs, AgentSonarCommands, BrowserProcAction,
    IgnoreDomainAction,
};
use killswitch_telemetry::agentsonar::{AgentSonarEngine, DynamicRuleSet};

#[test]
fn test_agentsonar_cli_commands_end_to_end() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "ks_cli_agentsonar_{}_{}",
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("cli_agentsonar.db");
    let db_str = db_path.to_string_lossy().to_string();

    let mk_args = |cmd: AgentSonarCommands| AgentSonarCliArgs {
        interface: "any".to_string(),
        enable_pid0: false,
        all: false,
        db_path: Some(db_str.clone()),
        config_path: None,
        command: Some(cmd),
    };

    // 1. Add & list agent rule
    handle_agentsonar(mk_args(AgentSonarCommands::Agents {
        action: AgentRuleAction::Add {
            agent: "cli-test-agent".to_string(),
            proc_pattern: "cli_worker*".to_string(),
            domain_pattern: "*.deepseek.com".to_string(),
        },
    }))
    .unwrap();
    handle_agentsonar(mk_args(AgentSonarCommands::Agents {
        action: AgentRuleAction::List,
    }))
    .unwrap();

    // 2. Add & list ignore domain and browser filter
    handle_agentsonar(mk_args(AgentSonarCommands::Ignore {
        action: IgnoreDomainAction::Add {
            domain: "cdn.noise.test".to_string(),
        },
    }))
    .unwrap();
    handle_agentsonar(mk_args(AgentSonarCommands::Browsers {
        action: BrowserProcAction::Add {
            proc_substring: "vivaldi".to_string(),
        },
    }))
    .unwrap();

    // 3. Update heuristic thresholds
    handle_agentsonar(mk_args(AgentSonarCommands::Heuristics {
        min_byte_ratio: Some(6.0),
        max_byte_ratio: None,
        weight_byte_asymmetry: None,
        min_pkt_ratio: Some(3.0),
        min_avg_pkt_in: None,
        max_avg_pkt_in: None,
        weight_pkt_streaming: None,
        min_duration_ms: Some(2000),
        max_duration_ms: None,
        weight_duration: None,
        weight_programmatic: None,
    }))
    .unwrap();

    // 4. Verify persistence via Engine + Import/Export + osquery-schema + non-interactive triage
    let engine = AgentSonarEngine::new(db_path.clone(), None).unwrap();
    let rules = engine.load_rules().unwrap();
    assert!(rules.agents.iter().any(|a| a.agent == "cli-test-agent"));
    assert!(rules.noise_domains.contains("cdn.noise.test"));
    assert!(rules.non_programmatic_procs.iter().any(|b| b == "vivaldi"));
    assert!((rules.heuristics.min_byte_ratio - 6.0).abs() < 1e-6);

    let export_file = dir.join("exported_rules.json");
    fs::write(&export_file, serde_json::to_string_pretty(&rules).unwrap()).unwrap();

    let db2_path = dir.join("imported_agentsonar.db");
    handle_agentsonar(AgentSonarCliArgs {
        interface: "any".to_string(),
        enable_pid0: false,
        all: false,
        db_path: Some(db2_path.to_string_lossy().to_string()),
        config_path: None,
        command: Some(AgentSonarCommands::Import {
            file: export_file.to_string_lossy().to_string(),
        }),
    })
    .unwrap();

    let imported_rules: DynamicRuleSet = AgentSonarEngine::new(db2_path, None)
        .unwrap()
        .load_rules()
        .unwrap();
    assert!(imported_rules
        .agents
        .iter()
        .any(|a| a.agent == "cli-test-agent"));

    handle_agentsonar(mk_args(AgentSonarCommands::OsquerySchema)).unwrap();
    handle_agentsonar(mk_args(AgentSonarCommands::Triage {
        min_score: 0.50,
        non_interactive: true,
    }))
    .unwrap();
    handle_agentsonar(mk_args(AgentSonarCommands::Status)).unwrap();

    // 5. Remove rule & noise domain
    handle_agentsonar(mk_args(AgentSonarCommands::Agents {
        action: AgentRuleAction::Remove {
            agent: "cli-test-agent".to_string(),
        },
    }))
    .unwrap();
    handle_agentsonar(mk_args(AgentSonarCommands::Ignore {
        action: IgnoreDomainAction::Remove {
            domain: "cdn.noise.test".to_string(),
        },
    }))
    .unwrap();

    let _ = fs::remove_dir_all(&dir);
}
