//! CLI handler for `killswitch siquery` subcommand.

use anyhow::{Context, Result};
use killswitch_telemetry::siquery::SiqueryEngine;

pub fn handle_siquery(
    query: Option<String>,
    format: &str,
    tables: bool,
    sweep: bool,
    _token: Option<String>,
) -> Result<()> {
    let engine = SiqueryEngine::new();

    if tables {
        println!(
            "Supported Siquery Relational Tables ({} total):",
            SiqueryEngine::list_tables().len()
        );
        for (i, tbl) in SiqueryEngine::list_tables().iter().enumerate() {
            println!("  {:2}. {}", i + 1, tbl);
        }
        return Ok(());
    }

    if sweep {
        println!("Executing 12-Sweep Active EDR Security and Host Audit...");
        let report = engine.run_siquery_edr_audit_sweep();
        let formatted = serde_json::to_string_pretty(&report)
            .context("Failed to serialize sweep report")?;
        println!("{}", formatted);
        return Ok(());
    }

    if let Some(sql) = query {
        match format.to_ascii_lowercase().as_str() {
            "csv" => {
                let csv = engine.execute_csv(&sql).map_err(|e| anyhow::anyhow!("{}", e))?;
                print!("{}", csv);
            }
            "json" => {
                let json = engine.execute_json(&sql).map_err(|e| anyhow::anyhow!("{}", e))?;
                println!("{}", json);
            }
            _ => {
                let pretty = engine
                    .execute_pretty(&sql)
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                println!("{}", pretty);
            }
        }
        return Ok(());
    }

    println!("Usage: killswitch siquery [--query <SQL>] [--format pretty|json|csv] [--tables] [--sweep]");
    println!("Run 'killswitch siquery --help' for details, or '--tables' to view all available relational tables.");
    Ok(())
}
