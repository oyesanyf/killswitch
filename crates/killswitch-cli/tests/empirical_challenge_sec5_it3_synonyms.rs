//! Empirical Adversarial Challenge SEC-5 Iteration 3 Synonyms:
//! Verifies canonical wire format synonyms across Claude, Cursor, Copilot, OpenCode, and MCP.

use killswitch_telemetry::agent_hooks::{
    clear_interceptions, evaluate_hook_synchronously, parse_claude_request, parse_copilot_request,
    parse_cursor_request, parse_opencode_request, GLOBAL_CORRELATOR,
};

#[test]
fn test_claude_tool_use_id_synonym() {
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_use_id": "tool-use-claude-9999",
        "tool_input": {
            "command": "ls -la"
        }
    })
    .to_string();
    let req = parse_claude_request(&payload, false).expect("parse claude");
    assert_eq!(
        req.session_id.as_deref(),
        Some("tool-use-claude-9999"),
        "Claude Code hook must extract session_id from 'tool_use_id'"
    );
}

#[test]
fn test_opencode_subcommand_and_working_file_synonyms() {
    let payload = serde_json::json!({
        "type": "before",
        "tool": "bash",
        "subcommand": "sudo rm -rf /",
        "working_file": "/etc/shadow"
    })
    .to_string();
    let req = parse_opencode_request(&payload).expect("parse opencode");
    assert_eq!(
        req.command.as_deref(),
        Some("sudo rm -rf /"),
        "OpenCode hook must extract command from 'subcommand'"
    );
    assert_eq!(
        req.file_path.as_deref(),
        Some("/etc/shadow"),
        "OpenCode hook must extract file_path from 'working_file'"
    );
    let decision = evaluate_hook_synchronously(&req);
    assert!(
        !decision.allowed,
        "Privileged command via subcommand and working_file must be denied"
    );
}

#[test]
fn test_cursor_context_paths_synonym() {
    let payload = serde_json::json!({
        "context_paths": ["/etc/shadow"]
    })
    .to_string();
    let req = parse_cursor_request(&payload, "beforeReadFile").expect("parse cursor");
    assert_eq!(
        req.file_path.as_deref(),
        Some("/etc/shadow"),
        "Cursor hook must extract file_path from 'context_paths'"
    );
    let decision = evaluate_hook_synchronously(&req);
    assert!(
        !decision.allowed,
        "Sensitive file read via context_paths must be denied"
    );
}

#[test]
fn test_cursor_cursor_command_synonym() {
    let payload = serde_json::json!({
        "cursor_command": "sudo rm -rf /"
    })
    .to_string();
    let req = parse_cursor_request(&payload, "beforeShellExecution").expect("parse cursor");
    assert_eq!(
        req.command.as_deref(),
        Some("sudo rm -rf /"),
        "Cursor hook must extract command from 'cursor_command'"
    );
    let decision = evaluate_hook_synchronously(&req);
    assert!(
        !decision.allowed,
        "Privileged command via cursor_command must be denied"
    );
}

#[test]
fn test_copilot_action_and_editor_context_synonyms() {
    let payload = serde_json::json!({
        "tool": "terminal",
        "copilot_action": "sudo rm -rf /",
        "editor_context": "/etc/shadow"
    })
    .to_string();
    let req = parse_copilot_request(&payload, "preToolUse").expect("parse copilot");
    assert_eq!(
        req.command.as_deref(),
        Some("sudo rm -rf /"),
        "Copilot hook must extract command from 'copilot_action'"
    );
    assert_eq!(
        req.file_path.as_deref(),
        Some("/etc/shadow"),
        "Copilot hook must extract file_path from 'editor_context'"
    );
    let decision = evaluate_hook_synchronously(&req);
    assert!(
        !decision.allowed,
        "Privileged command via copilot_action must be denied"
    );
}

#[test]
fn test_mcp_tool_result_synonym_incident_a_correlation() {
    clear_interceptions();
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "session_id": "session-mcp-tool-result",
        "tool_result": {
            "exit_code": 1,
            "stderr": "sudo: a password is required"
        }
    })
    .to_string();
    let req = parse_claude_request(&payload, true).expect("parse post tool");
    assert_eq!(req.exit_code, Some(1), "tool_result must extract exit_code");
    assert_eq!(
        req.stderr.as_deref(),
        Some("sudo: a password is required"),
        "tool_result must extract stderr"
    );
    let decision = evaluate_hook_synchronously(&req);
    assert!(decision.allowed);
    assert!(
        GLOBAL_CORRELATOR.active_denial_count() > 0,
        "Correlator must record dynamic denial from 'tool_result'"
    );
}
