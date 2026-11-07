use std::path::PathBuf;
use tempfile::tempdir;

use killswitch_telemetry::agent_hooks::{
    clear_interceptions, evaluate_hook_synchronously, format_claude_response,
    format_copilot_response, format_cursor_response, format_mcp_error_response,
    format_opencode_response, get_recent_interceptions, install_agent_hooks, parse_claude_request,
    parse_copilot_request, parse_cursor_request, parse_mcp_call_request, parse_opencode_request,
    HookEventType, NormalizedHookRequest, SupportedAgentKind, GLOBAL_CORRELATOR,
};

#[test]
fn test_claude_code_pre_and_post_parsers_and_formatters() {
    let pre_payload = r#"{
        "tool_name": "Bash",
        "tool_input": {
            "command": "git status"
        }
    }"#;

    let req = parse_claude_request(pre_payload, false).expect("parse claude pre");
    assert_eq!(req.agent, SupportedAgentKind::Claude);
    assert_eq!(req.event_type, HookEventType::PreToolUse);
    assert_eq!(req.command.as_deref(), Some("git status"));

    let decision = evaluate_hook_synchronously(&req);
    assert!(decision.allowed);
    let (code, stderr) = format_claude_response(&decision);
    assert_eq!(code, 0);
    assert!(stderr.is_empty());

    // Test denied privilege command
    let pre_priv = r#"{
        "tool_name": "Bash",
        "tool_input": {
            "command": "sudo rm -rf /"
        }
    }"#;
    let priv_req = parse_claude_request(pre_priv, false).expect("parse claude priv");
    let priv_decision = evaluate_hook_synchronously(&priv_req);
    assert!(!priv_decision.allowed);
    assert!(priv_decision.denied_by_layer.is_some());
    let (priv_code, priv_stderr) = format_claude_response(&priv_decision);
    assert_eq!(priv_code, 2);
    assert!(priv_stderr.contains("Privileged command elevation rejected"));
}

#[test]
fn test_cursor_wire_format_and_dlp_rejection() {
    let before_shell = r#"{
        "command": "echo 'CONFIDENTIAL patient clinical record: SSN 123-45-6789 with severe diagnosis'",
        "cwd": "/workspace"
    }"#;

    let req = parse_cursor_request(before_shell, "beforeShellExecution").expect("parse cursor");
    assert_eq!(req.agent, SupportedAgentKind::Cursor);
    assert_eq!(req.event_type, HookEventType::BeforeShellExecution);

    let decision = evaluate_hook_synchronously(&req);
    assert!(!decision.allowed);
    assert_eq!(
        decision.denied_by_layer.as_deref(),
        Some("Layer 3: SemanticDlpEngine")
    );

    let (code, stdout) = format_cursor_response(&decision);
    assert_eq!(code, 0);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("parse cursor response json");
    assert_eq!(json["permission"], "deny");
    assert!(json["agent_message"]
        .as_str()
        .unwrap()
        .contains("Sensitive data"));
}

#[test]
fn test_copilot_and_opencode_parsers() {
    let copilot_payload = r#"{
        "tool": "terminal.execute",
        "parameters": {
            "command": "cargo test"
        }
    }"#;
    let req = parse_copilot_request(copilot_payload, "preToolUse").expect("parse copilot");
    assert_eq!(req.agent, SupportedAgentKind::Copilot);
    let decision = evaluate_hook_synchronously(&req);
    assert!(decision.allowed);
    let (code, stdout) = format_copilot_response(&decision);
    assert_eq!(code, 0);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("copilot json");
    assert_eq!(json["permissionDecision"], "allow");

    let opencode_payload = r#"{
        "tool": "bash",
        "args": {
            "command": "npm install"
        },
        "type": "before"
    }"#;
    let opencode_req = parse_opencode_request(opencode_payload).expect("parse opencode");
    assert_eq!(opencode_req.agent, SupportedAgentKind::OpenCode);
    let opencode_decision = evaluate_hook_synchronously(&opencode_req);
    assert!(opencode_decision.allowed);
    let (opencode_code, opencode_stdout) = format_opencode_response(&opencode_decision);
    assert_eq!(opencode_code, 0);
    let opencode_json: serde_json::Value =
        serde_json::from_str(&opencode_stdout).expect("opencode json");
    assert_eq!(opencode_json["allow"], true);
}

#[test]
fn test_mcp_tools_call_interception() {
    let mcp_call = r#"{
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {
            "name": "bash",
            "arguments": {
                "command": "sudo cat /etc/shadow"
            }
        }
    }"#;

    let req = parse_mcp_call_request(mcp_call).expect("parse mcp call");
    assert_eq!(req.agent, SupportedAgentKind::Mcp);
    let decision = evaluate_hook_synchronously(&req);
    assert!(!decision.allowed);

    let err_resp = format_mcp_error_response(&serde_json::json!(42), &decision);
    let val: serde_json::Value = serde_json::from_str(&err_resp).expect("mcp json parse");
    assert_eq!(val["id"], 42);
    assert_eq!(val["result"]["isError"], true);
    assert!(val["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("Policy Violation"));
}

#[test]
fn test_incident_a_post_tool_denial_correlation() {
    let session_id = "test-session-incident-a";

    // Step 1: Simulate PostToolUse where an agent ran `sudo -n id` and was denied
    let post_payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": "sudo -n id"
        },
        "tool_response": {
            "exit_code": 1,
            "stderr": "sudo: a password is required"
        },
        "session_id": session_id
    })
    .to_string();

    let post_req = parse_claude_request(&post_payload, true).expect("parse claude post");
    let post_decision = evaluate_hook_synchronously(&post_req);
    assert!(post_decision.allowed); // PostToolUse records and returns allow

    assert!(GLOBAL_CORRELATOR.active_denial_count() > 0);

    // Step 2: Now agent tries cross-boundary equivalent `wsl -u root id`
    let retry_payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": "wsl -u root id"
        },
        "session_id": session_id
    })
    .to_string();

    let retry_req = parse_claude_request(&retry_payload, false).expect("parse claude retry");
    let retry_decision = evaluate_hook_synchronously(&retry_req);
    assert!(!retry_decision.allowed);
    assert!(
        retry_decision.rationale.contains("Incident A")
            || retry_decision.rationale.contains("Privileged")
    );
}

#[test]
fn test_agent_interceptions_ring_buffer() {
    clear_interceptions();

    for i in 0..15 {
        let req = NormalizedHookRequest {
            agent: SupportedAgentKind::Claude,
            event_type: HookEventType::PreToolUse,
            tool_name: Some("test_tool".into()),
            command: Some(format!("echo hello {i}")),
            file_path: None,
            arguments: None,
            exit_code: None,
            stderr: None,
            cwd: None,
            session_id: Some("session-1".into()),
            rpc_id: None,
        };
        let _ = evaluate_hook_synchronously(&req);
    }

    let recent = get_recent_interceptions(5);
    assert_eq!(recent.len(), 5);
    assert_eq!(recent[0].command, "echo hello 14");
    assert_eq!(recent[1].command, "echo hello 13");
}

#[test]
fn test_install_agent_hooks() {
    let tmp = tempdir().expect("tempdir");
    let ws = tmp.path();
    let bin_path = PathBuf::from("d:\\harfile\\killswitch\\target\\debug\\killswitch.exe");

    let agents = vec![
        SupportedAgentKind::Claude,
        SupportedAgentKind::Cursor,
        SupportedAgentKind::Copilot,
        SupportedAgentKind::OpenCode,
    ];

    let created = install_agent_hooks(ws, &agents, &bin_path).expect("install hooks");
    assert_eq!(created.len(), 4);

    assert!(ws.join(".claude").join("settings.json").exists());
    assert!(ws.join(".cursor").join("hooks.json").exists());
    assert!(ws
        .join(".github")
        .join("hooks")
        .join("killswitch.json")
        .exists());
    assert!(ws
        .join(".opencode")
        .join("plugin")
        .join("killswitch-guard.js")
        .exists());

    // Verify Claude settings content
    let claude_content = std::fs::read_to_string(ws.join(".claude").join("settings.json")).unwrap();
    assert!(claude_content.contains("PreToolUse"));
    assert!(claude_content.contains("hook evaluate --agent claude"));

    // Verify Cursor content
    let cursor_content = std::fs::read_to_string(ws.join(".cursor").join("hooks.json")).unwrap();
    assert!(cursor_content.contains("beforeShellExecution"));
}

#[test]
fn test_mcp_rpc_id_preservation_string_number_null() {
    // Case 1: String UUID ID
    let raw_uuid = r#"{
        "jsonrpc": "2.0",
        "id": "c0a80101-1234-5678-9abc-def012345678",
        "method": "tools/call",
        "params": {
            "name": "bash",
            "arguments": {
                "command": "sudo rm -rf /"
            }
        }
    }"#;
    let req = parse_mcp_call_request(raw_uuid).expect("parse uuid mcp");
    assert_eq!(req.agent, SupportedAgentKind::Mcp);
    assert_eq!(
        req.rpc_id,
        Some(serde_json::json!("c0a80101-1234-5678-9abc-def012345678"))
    );
    let decision = evaluate_hook_synchronously(&req);
    assert!(!decision.allowed);
    let resp = format_mcp_error_response(
        req.rpc_id.as_ref().unwrap_or(&serde_json::Value::Null),
        &decision,
    );
    let json: serde_json::Value = serde_json::from_str(&resp).expect("parse json");
    assert_eq!(json["id"], "c0a80101-1234-5678-9abc-def012345678");
    assert_eq!(json["result"]["isError"], true);

    // Case 2: Numeric ID
    let raw_num = r#"{
        "jsonrpc": "2.0",
        "id": 987654,
        "method": "tools/call",
        "params": {
            "name": "bash",
            "arguments": {
                "command": "sudo cat /etc/shadow"
            }
        }
    }"#;
    let req_num = parse_mcp_call_request(raw_num).expect("parse num mcp");
    assert_eq!(req_num.rpc_id, Some(serde_json::json!(987654)));
    let dec_num = evaluate_hook_synchronously(&req_num);
    assert!(!dec_num.allowed);
    let resp_num = format_mcp_error_response(
        req_num.rpc_id.as_ref().unwrap_or(&serde_json::Value::Null),
        &dec_num,
    );
    let json_num: serde_json::Value = serde_json::from_str(&resp_num).expect("parse json");
    assert_eq!(json_num["id"], 987654);

    // Case 3: Explicit Null ID
    let raw_null = r#"{
        "jsonrpc": "2.0",
        "id": null,
        "method": "tools/call",
        "params": {
            "name": "bash",
            "arguments": {
                "command": "sudo shutdown -h now"
            }
        }
    }"#;
    let req_null = parse_mcp_call_request(raw_null).expect("parse null mcp");
    assert_eq!(req_null.rpc_id, Some(serde_json::Value::Null));
    let dec_null = evaluate_hook_synchronously(&req_null);
    let resp_null = format_mcp_error_response(
        req_null.rpc_id.as_ref().unwrap_or(&serde_json::Value::Null),
        &dec_null,
    );
    let json_null: serde_json::Value = serde_json::from_str(&resp_null).expect("parse json");
    assert!(json_null["id"].is_null());

    // Case 4: Omitted ID (Notification)
    let raw_omit = r#"{
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "bash",
            "arguments": {
                "command": "sudo reboot"
            }
        }
    }"#;
    let req_omit = parse_mcp_call_request(raw_omit).expect("parse omit mcp");
    assert_eq!(req_omit.rpc_id, None);
    let dec_omit = evaluate_hook_synchronously(&req_omit);
    let resp_omit = format_mcp_error_response(
        req_omit.rpc_id.as_ref().unwrap_or(&serde_json::Value::Null),
        &dec_omit,
    );
    let json_omit: serde_json::Value = serde_json::from_str(&resp_omit).expect("parse json");
    assert!(json_omit["id"].is_null());
}

#[test]
fn test_sensitive_root_credential_path_interception_pre_tool() {
    // 1. Unprivileged tool reading /etc/shadow via cat
    let claude_payload = r#"{
        "tool_name": "Bash",
        "tool_input": {
            "command": "cat /etc/shadow"
        }
    }"#;
    let req = parse_claude_request(claude_payload, false).expect("parse claude");
    let decision = evaluate_hook_synchronously(&req);
    assert!(!decision.allowed);
    assert!(decision
        .rationale
        .contains("sensitive system credential store"));

    // 2. Cursor beforeReadFile on /etc/sudoers
    let cursor_payload = r#"{
        "file_path": "/etc/sudoers"
    }"#;
    let cursor_req = parse_cursor_request(cursor_payload, "beforeReadFile").expect("parse cursor");
    let cursor_decision = evaluate_hook_synchronously(&cursor_req);
    assert!(!cursor_decision.allowed);
    assert!(cursor_decision
        .rationale
        .contains("sensitive system credential store"));

    // 3. MCP read_file tool with SAM registry hive path
    let mcp_payload = r#"{
        "jsonrpc": "2.0",
        "id": "mcp-sam-read",
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {
                "path": "C:\\Windows\\System32\\config\\SAM"
            }
        }
    }"#;
    let mcp_req = parse_mcp_call_request(mcp_payload).expect("parse mcp");
    let mcp_decision = evaluate_hook_synchronously(&mcp_req);
    assert!(!mcp_decision.allowed);
    assert!(mcp_decision
        .rationale
        .contains("sensitive system credential store"));
}
