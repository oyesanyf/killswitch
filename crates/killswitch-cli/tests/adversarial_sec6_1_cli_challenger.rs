//! Tier 5 Adversarial CLI Coverage Hardening & Gap Analysis Test Suite (SEC-6-1)
//!
//! Author: challenger_sec6_1 (Teamwork Empirical Challenger)
//! Scope:
//! - `crates/killswitch-cli/src/hook_cli.rs`
//! - `crates/killswitch-cli/src/siquery_cli.rs`
//! - Agent hook evaluators, installers, formatters, and siquery runners

use tempfile::tempdir;

use killswitch_cli::hook_cli::handle_hook_install;
use killswitch_cli::siquery_cli::handle_siquery;
use killswitch_telemetry::agent_hooks::{
    format_claude_response, format_copilot_response, format_cursor_response,
    format_mcp_error_response, format_opencode_response, install_agent_hooks,
    HookEvaluationDecision, SupportedAgentKind,
};

#[test]
fn test_cli_siquery_subcommand_dispatch_and_formats() {
    // 1. Table inventory flag
    let res_tables = handle_siquery(None, "pretty", true, false, None);
    assert!(res_tables.is_ok(), "siquery --tables must succeed");

    // 2. 12-Sweep EDR active audit flag
    let res_sweep = handle_siquery(None, "json", false, true, None);
    assert!(res_sweep.is_ok(), "siquery --sweep must succeed");

    // 3. Format tests: CSV, JSON, Pretty
    let test_query = Some("SELECT pid, name FROM processes LIMIT 3;".to_string());

    let res_csv = handle_siquery(test_query.clone(), "csv", false, false, None);
    assert!(res_csv.is_ok(), "siquery --format csv must succeed");

    let res_json = handle_siquery(test_query.clone(), "json", false, false, None);
    assert!(res_json.is_ok(), "siquery --format json must succeed");

    let res_pretty = handle_siquery(test_query, "pretty", false, false, None);
    assert!(res_pretty.is_ok(), "siquery --format pretty must succeed");

    // 4. Mutating SQL queries must be rejected with error
    let mutating_query = Some("DROP TABLE processes;".to_string());
    let res_mutating = handle_siquery(mutating_query, "pretty", false, false, None);
    assert!(
        res_mutating.is_err(),
        "siquery must fail closed on mutating statements"
    );
}

#[test]
fn test_cli_hook_installer_and_config_validation() {
    let tmp = tempdir().expect("tempdir");
    let ws = tmp.path().to_path_buf();
    let bin_path = ws.join("bin").join("killswitch.exe");
    std::fs::create_dir_all(bin_path.parent().unwrap()).unwrap();
    std::fs::write(&bin_path, b"dummy binary").unwrap();

    // 1. Install all agents
    let agents = vec![
        SupportedAgentKind::Claude,
        SupportedAgentKind::Cursor,
        SupportedAgentKind::Copilot,
        SupportedAgentKind::OpenCode,
    ];
    let created = install_agent_hooks(&ws, &agents, &bin_path).expect("install_agent_hooks");
    assert_eq!(created.len(), 4);

    // Verify Claude settings.json
    let claude_file = ws.join(".claude").join("settings.json");
    assert!(claude_file.exists());
    let claude_val: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&claude_file).unwrap()).unwrap();
    assert!(claude_val["hooks"]["PreToolUse"].is_array());
    assert!(claude_val["hooks"]["PostToolUse"].is_array());

    // Verify Cursor hooks.json
    let cursor_file = ws.join(".cursor").join("hooks.json");
    assert!(cursor_file.exists());
    let cursor_val: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&cursor_file).unwrap()).unwrap();
    assert!(cursor_val["hooks"]["beforeShellExecution"].is_array());
    assert!(cursor_val["hooks"]["afterShellExecution"].is_array());
    assert!(cursor_val["hooks"]["beforeMCPExecution"].is_array());
    assert!(cursor_val["hooks"]["beforeReadFile"].is_array());

    // Verify Copilot killswitch.json
    let copilot_file = ws.join(".github").join("hooks").join("killswitch.json");
    assert!(copilot_file.exists());
    let copilot_val: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&copilot_file).unwrap()).unwrap();
    assert!(copilot_val["hooks"]["preToolUse"].is_array());
    assert!(copilot_val["hooks"]["postToolUse"].is_array());

    // Verify OpenCode plugin
    let opencode_file = ws
        .join(".opencode")
        .join("plugin")
        .join("killswitch-guard.js");
    assert!(opencode_file.exists());
    let script = std::fs::read_to_string(&opencode_file).unwrap();
    assert!(script.contains("killswitch-guard"));
    assert!(script.contains("onToolExecuteBefore"));
    assert!(script.contains("onToolExecuteAfter"));

    // Test handle_hook_install with selective agent string
    let tmp2 = tempdir().expect("tempdir2");
    let res = handle_hook_install(
        Some(tmp2.path().to_path_buf()),
        Some("claude,cursor".to_string()),
    );
    assert!(res.is_ok());
    assert!(tmp2.path().join(".claude").join("settings.json").exists());
    assert!(tmp2.path().join(".cursor").join("hooks.json").exists());
    assert!(!tmp2.path().join(".opencode").exists());
}

#[test]
fn test_cli_all_agent_formatters_protocol_adherence() {
    // 1. Claude Code
    let allow_dec = HookEvaluationDecision::allow("Allowed by test", 100);
    let deny_dec = HookEvaluationDecision::deny(
        "Privilege escalation blocked",
        Some("Layer 1"),
        Some("Use unprivileged user"),
        150,
    );

    let (c_code, c_err) = format_claude_response(&allow_dec);
    assert_eq!(c_code, 0);
    assert!(c_err.is_empty());

    let (c_deny_code, c_deny_err) = format_claude_response(&deny_dec);
    assert_eq!(c_deny_code, 2, "Claude Code deny must exit with code 2");
    assert!(c_deny_err.contains("KillSwitch Hook Policy Denied"));
    assert!(c_deny_err.contains("Privilege escalation blocked"));

    // 2. Cursor
    let (cur_allow_code, cur_allow_out) = format_cursor_response(&allow_dec);
    assert_eq!(cur_allow_code, 0);
    let cur_allow_json: serde_json::Value = serde_json::from_str(&cur_allow_out).unwrap();
    assert_eq!(cur_allow_json["permission"], "allow");

    let (cur_deny_code, cur_deny_out) = format_cursor_response(&deny_dec);
    assert_eq!(cur_deny_code, 0);
    let cur_deny_json: serde_json::Value = serde_json::from_str(&cur_deny_out).unwrap();
    assert_eq!(cur_deny_json["permission"], "deny");
    assert!(cur_deny_json["agent_message"]
        .as_str()
        .unwrap()
        .contains("Privilege escalation blocked"));

    // 3. GitHub Copilot
    let (cop_allow_code, cop_allow_out) = format_copilot_response(&allow_dec);
    assert_eq!(cop_allow_code, 0);
    let cop_allow_json: serde_json::Value = serde_json::from_str(&cop_allow_out).unwrap();
    assert_eq!(cop_allow_json["permissionDecision"], "allow");

    let (cop_deny_code, cop_deny_out) = format_copilot_response(&deny_dec);
    assert_eq!(cop_deny_code, 0);
    let cop_deny_json: serde_json::Value = serde_json::from_str(&cop_deny_out).unwrap();
    assert_eq!(cop_deny_json["permissionDecision"], "deny");
    assert!(cop_deny_json["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .contains("Privilege escalation blocked"));

    // 4. OpenCode
    let (oc_allow_code, oc_allow_out) = format_opencode_response(&allow_dec);
    assert_eq!(oc_allow_code, 0);
    let oc_allow_json: serde_json::Value = serde_json::from_str(&oc_allow_out).unwrap();
    assert_eq!(oc_allow_json["allow"], true);

    let (oc_deny_code, oc_deny_out) = format_opencode_response(&deny_dec);
    assert_eq!(oc_deny_code, 0);
    let oc_deny_json: serde_json::Value = serde_json::from_str(&oc_deny_out).unwrap();
    assert_eq!(oc_deny_json["allow"], false);
    assert!(oc_deny_json["reason"]
        .as_str()
        .unwrap()
        .contains("Privilege escalation blocked"));

    // 5. MCP JSON-RPC
    let mcp_err_str = format_mcp_error_response(&serde_json::json!("mcp-id-123"), &deny_dec);
    let mcp_json: serde_json::Value = serde_json::from_str(&mcp_err_str).unwrap();
    assert_eq!(mcp_json["jsonrpc"], "2.0");
    assert_eq!(mcp_json["id"], "mcp-id-123");
    assert_eq!(mcp_json["error"]["code"], -32000);
    assert_eq!(mcp_json["error"]["data"]["denied_by_layer"], "Layer 1");
    assert_eq!(
        mcp_json["error"]["data"]["suggested_remediation"],
        "Use unprivileged user"
    );
    assert_eq!(mcp_json["result"]["isError"], true);
}
