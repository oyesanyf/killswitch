//! # CLI Subcommands for Agent Hooks & MCP Proxy
//!
//! Provides the command-line entry points for:
//! - `killswitch hook install --workspace <dir> --agents ...`
//! - `killswitch hook evaluate --agent <kind> [--event <name>] [--post]`
//! - `killswitch mcp-proxy -- <command> [args...]`

use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;

use anyhow::{bail, Context, Result};
use killswitch_telemetry::agent_hooks::{
    evaluate_hook_synchronously, format_claude_response, format_copilot_response,
    format_cursor_response, format_mcp_error_response, format_opencode_response,
    install_agent_hooks, parse_claude_request, parse_copilot_request, parse_cursor_request,
    parse_mcp_call_request, parse_opencode_request, SupportedAgentKind,
};

/// Installs hook configurations across specified agent configuration files in a workspace.
pub fn handle_hook_install(workspace: Option<PathBuf>, agents: Option<String>) -> Result<()> {
    let ws = workspace.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let bin_path = std::env::current_exe().context("Failed to resolve current killswitch binary path")?;

    let agent_kinds = if let Some(agent_str) = agents {
        let mut list = Vec::new();
        for item in agent_str.split(',') {
            if let Some(kind) = SupportedAgentKind::from_str(item) {
                list.push(kind);
            } else {
                eprintln!("⚠️  Unknown agent kind: '{}'. Skipping.", item);
            }
        }
        if list.is_empty() {
            vec![
                SupportedAgentKind::Claude,
                SupportedAgentKind::Cursor,
                SupportedAgentKind::Copilot,
                SupportedAgentKind::OpenCode,
            ]
        } else {
            list
        }
    } else {
        vec![
            SupportedAgentKind::Claude,
            SupportedAgentKind::Cursor,
            SupportedAgentKind::Copilot,
            SupportedAgentKind::OpenCode,
        ]
    };

    println!("================================================================================");
    println!("🛡️  INSTALLING KILLSWITCH SYNCHRONOUS AGENT HOOKS");
    println!("================================================================================");
    println!("  Workspace Directory: {}", ws.display());
    println!("  KillSwitch Binary:   {}", bin_path.display());
    println!("  Target Agent Kinds:  {:?}", agent_kinds);
    println!("--------------------------------------------------------------------------------");

    let installed = install_agent_hooks(&ws, &agent_kinds, &bin_path)
        .context("Failed to install agent hook configurations")?;

    for p in &installed {
        println!("  ✅ Created hook config: {}", p.display());
    }
    println!("\n✨ Successfully installed {} agent hook configs.", installed.len());
    Ok(())
}

/// Evaluates an agent hook request reading JSON from stdin and returning formatted protocol output.
pub fn handle_hook_evaluate(agent: &str, event: Option<&str>, is_post: bool) -> Result<()> {
    let agent_kind = SupportedAgentKind::from_str(agent)
        .ok_or_else(|| anyhow::anyhow!("Unsupported agent kind: '{}'", agent))?;

    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .context("Failed to read JSON payload from standard input")?;

    if input.trim().is_empty() {
        bail!("Empty payload received on stdin for agent '{}'", agent);
    }

    let req = match agent_kind {
        SupportedAgentKind::Claude => {
            parse_claude_request(&input, is_post).map_err(|e| anyhow::anyhow!(e))?
        }
        SupportedAgentKind::Cursor => {
            let evt = event.unwrap_or(if is_post {
                "afterShellExecution"
            } else {
                "beforeShellExecution"
            });
            parse_cursor_request(&input, evt).map_err(|e| anyhow::anyhow!(e))?
        }
        SupportedAgentKind::Copilot => {
            let evt = event.unwrap_or(if is_post { "postToolUse" } else { "preToolUse" });
            parse_copilot_request(&input, evt).map_err(|e| anyhow::anyhow!(e))?
        }
        SupportedAgentKind::OpenCode => {
            parse_opencode_request(&input).map_err(|e| anyhow::anyhow!(e))?
        }
        SupportedAgentKind::Mcp => {
            parse_mcp_call_request(&input).map_err(|e| anyhow::anyhow!(e))?
        }
    };

    let decision = evaluate_hook_synchronously(&req);

    match agent_kind {
        SupportedAgentKind::Claude => {
            let (exit_code, stderr) = format_claude_response(&decision);
            if !stderr.is_empty() {
                eprint!("{stderr}");
            }
            std::process::exit(exit_code);
        }
        SupportedAgentKind::Cursor => {
            let (exit_code, stdout) = format_cursor_response(&decision);
            println!("{stdout}");
            std::process::exit(exit_code);
        }
        SupportedAgentKind::Copilot => {
            let (exit_code, stdout) = format_copilot_response(&decision);
            println!("{stdout}");
            std::process::exit(exit_code);
        }
        SupportedAgentKind::OpenCode => {
            let (exit_code, stdout) = format_opencode_response(&decision);
            println!("{stdout}");
            std::process::exit(exit_code);
        }
        SupportedAgentKind::Mcp => {
            let dummy_id = serde_json::json!(1);
            if !decision.allowed {
                println!("{}", format_mcp_error_response(&dummy_id, &decision));
                std::process::exit(0);
            } else {
                std::process::exit(0);
            }
        }
    }
}

/// Runs the MCP stdio proxy, intercepting and evaluating `tools/call` JSON-RPC lines in-flight.
pub fn handle_mcp_proxy(command: String, args: Vec<String>) -> Result<()> {
    let mut child = Command::new(&command)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("Failed to spawn child MCP server: {} {:?}", command, args))?;

    let child_stdin = child
        .stdin
        .take()
        .context("Failed to capture child stdin handle")?;
    let child_stdout = child
        .stdout
        .take()
        .context("Failed to capture child stdout handle")?;

    // Thread 1: Stream child stdout to parent stdout
    let stdout_handle = thread::spawn(move || {
        let reader = BufReader::new(child_stdout);
        let mut out = io::stdout().lock();
        for line in reader.lines() {
            if let Ok(l) = line {
                let _ = writeln!(out, "{l}");
                let _ = out.flush();
            } else {
                break;
            }
        }
    });

    // Thread 2: Inspect incoming lines on parent stdin before sending to child
    let mut child_stdin_writer = child_stdin;
    let parent_stdin = io::stdin();
    for line in parent_stdin.lock().lines() {
        let l = match line {
            Ok(v) => v,
            Err(_) => break,
        };

        if l.trim().is_empty() {
            continue;
        }

        // Check if this line is an MCP tools/call
        let mut should_forward = true;
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&l) {
            if val.get("method").and_then(|m| m.as_str()) == Some("tools/call") {
                if let Ok(req) = parse_mcp_call_request(&l) {
                    let decision = evaluate_hook_synchronously(&req);
                    if !decision.allowed {
                        should_forward = false;
                        let id = val.get("id").unwrap_or(&serde_json::Value::Null);
                        let err_resp = format_mcp_error_response(id, &decision);
                        let mut out = io::stdout().lock();
                        let _ = writeln!(out, "{err_resp}");
                        let _ = out.flush();
                    }
                }
            }
        }

        if should_forward
            && (writeln!(child_stdin_writer, "{l}").is_err() || child_stdin_writer.flush().is_err())
        {
            break;
        }
    }

    drop(child_stdin_writer);
    let _ = stdout_handle.join();
    let status = child.wait().context("Failed to wait on child MCP server")?;
    std::process::exit(status.code().unwrap_or(0));
}
