//! Adversarial Challenge SEC-5 Iteration 2 / Iteration 4:
//! MCP JSON-RPC ID Preservation, Wire Format Synonyms, and Error Formatting Compliance.
//!
//! Evaluates the deliverables of Milestone SEC-5:
//! 1. JSON-RPC ID preservation across diverse types:
//!    - String IDs (UUIDs, alphanumeric, special characters)
//!    - Large integer IDs (e.g. 9007199254740991, i64::MAX)
//!    - Negative integer IDs (-42, -1, i64::MIN)
//!    - Explicit null ID ("id": null)
//!    - Missing "id" field (JSON-RPC notification behavior)
//! 2. Wire format synonym variations:
//!    - Tool name synonyms: `tool_name`, `name`, `tool`
//!    - Tool argument synonyms: `tool_input`, `arguments`, `args`, `parameters`, `input`
//!    - Tool response synonyms: `tool_response`, `tool_result`, `result`, `content`, `output`
//!    - Command synonyms: `command`, `cmd`, `cursor_command`, `copilot_action`, `subcommand`, `action`
//!    - Path synonyms: `file_path`, `path`, `filePath`, `uri`, `working_file`, `editor_context`, `file`, `context_paths`
//!    - Session / tool ID synonyms: `session_id`, `sessionId`, `conversation_id`, `cursor_trace_id`, `tool_use_id`
//!    - Agent / source ID helpers: `extract_wire_agent_id`, `extract_wire_source_agent_id`
//! 3. MCP error response formatting compliance (JSON-RPC 2.0 §5.1):
//!    - Response structure: `{"jsonrpc": "2.0", "id": <exact_id>, "error": {"code": -32000, "message": "...", "data": ...}}`
//!    - Verify zero ID clobbering, zero fallback to static 1 or null when an ID was provided.

use std::sync::Mutex;

use killswitch_telemetry::agent_hooks::{
    clear_interceptions, evaluate_hook_synchronously, extract_wire_agent_id,
    extract_wire_source_agent_id, format_mcp_error_response, parse_claude_request,
    parse_copilot_request, parse_cursor_request, parse_mcp_call_request, parse_opencode_request,
    HookEvaluationDecision, GLOBAL_CORRELATOR,
};

static ADVERSARIAL_TEST_LOCK: Mutex<()> = Mutex::new(());

// ============================================================================
// 1. JSON-RPC ID Preservation Across Diverse Types
// ============================================================================

#[test]
fn test_jsonrpc_id_preservation_string_types() {
    let test_strings = vec![
        "req-uuid-c0a80101-1234-5678-9abc-def012345678",
        "alphanumeric_123_XYZ",
        "symbols/colons:slashes?query=1&var=foo#hash",
        "with whitespace in id",
        "", // empty string is valid JSON string ID
    ];

    for s in test_strings {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": s,
            "method": "tools/call",
            "params": {
                "name": "bash",
                "arguments": {
                    "command": "sudo rm -rf /"
                }
            }
        })
        .to_string();

        let req = parse_mcp_call_request(&payload).expect("parse string id mcp");
        assert_eq!(req.rpc_id, Some(serde_json::Value::String(s.to_string())));

        let decision = evaluate_hook_synchronously(&req);
        assert!(!decision.allowed);

        let resp_str = format_mcp_error_response(
            req.rpc_id.as_ref().unwrap_or(&serde_json::Value::Null),
            &decision,
        );
        let resp_val: serde_json::Value =
            serde_json::from_str(&resp_str).expect("parse json response");
        assert_eq!(
            resp_val["id"],
            serde_json::Value::String(s.to_string()),
            "String ID '{}' must be preserved verbatim",
            s
        );
    }
}

#[test]
fn test_jsonrpc_id_preservation_large_and_negative_integers() {
    let test_integers: Vec<i64> = vec![
        0,
        1,
        42,
        -1,
        -42,
        -999999,
        9007199254740991_i64,  // Number.MAX_SAFE_INTEGER (2^53 - 1)
        -9007199254740991_i64, // Number.MIN_SAFE_INTEGER
        i64::MAX,
        i64::MIN,
    ];

    for num in test_integers {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": num,
            "method": "tools/call",
            "params": {
                "name": "bash",
                "arguments": {
                    "command": "sudo rm -rf /"
                }
            }
        })
        .to_string();

        let req = parse_mcp_call_request(&payload).expect("parse integer id mcp");
        assert_eq!(req.rpc_id, Some(serde_json::json!(num)));

        let decision = evaluate_hook_synchronously(&req);
        assert!(!decision.allowed);

        let resp_str = format_mcp_error_response(
            req.rpc_id.as_ref().unwrap_or(&serde_json::Value::Null),
            &decision,
        );
        let resp_val: serde_json::Value =
            serde_json::from_str(&resp_str).expect("parse json response");
        assert_eq!(
            resp_val["id"],
            serde_json::json!(num),
            "Integer ID '{}' must be preserved verbatim",
            num
        );
    }
}

#[test]
fn test_jsonrpc_id_preservation_null_and_missing() {
    // 1. Explicit null ID
    let null_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "method": "tools/call",
        "params": {
            "name": "bash",
            "arguments": {
                "command": "sudo rm -rf /"
            }
        }
    })
    .to_string();

    let null_req = parse_mcp_call_request(&null_payload).expect("parse null id mcp");
    assert_eq!(null_req.rpc_id, Some(serde_json::Value::Null));
    let null_dec = evaluate_hook_synchronously(&null_req);
    assert!(!null_dec.allowed);

    let null_resp = format_mcp_error_response(
        null_req.rpc_id.as_ref().unwrap_or(&serde_json::Value::Null),
        &null_dec,
    );
    let null_val: serde_json::Value = serde_json::from_str(&null_resp).unwrap();
    assert!(
        null_val["id"].is_null(),
        "Explicit null ID must remain null"
    );

    // 2. Missing ID (JSON-RPC Notification)
    let notif_payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "bash",
            "arguments": {
                "command": "sudo rm -rf /"
            }
        }
    })
    .to_string();

    let notif_req = parse_mcp_call_request(&notif_payload).expect("parse notification mcp");
    assert_eq!(notif_req.rpc_id, None, "Missing id must parse as None");
}

// ============================================================================
// 2. MCP Error Response Formatting Compliance (JSON-RPC 2.0 §5.1)
// ============================================================================

#[test]
fn test_mcp_error_response_structure_compliance() {
    let dummy_decision = HookEvaluationDecision::deny(
        "Privileged command elevation rejected",
        Some("Layer 1: SemanticCommandAst"),
        Some("Use unprivileged command"),
        25,
    );

    let id = serde_json::json!("req-test-123");
    let resp = format_mcp_error_response(&id, &dummy_decision);
    let val: serde_json::Value = serde_json::from_str(&resp).expect("valid json response");

    // JSON-RPC 2.0 header checks
    assert_eq!(val["jsonrpc"], "2.0", "Must have jsonrpc: 2.0");
    assert_eq!(val["id"], id, "Must echo client id verbatim");

    // Check whether the response conforms to JSON-RPC 2.0 §5.1 error response:
    // {"jsonrpc": "2.0", "id": ..., "error": {"code": -32000, "message": "...", "data": ...}}
    // OR MCP CallToolResult with result.isError: true:
    // {"jsonrpc": "2.0", "id": ..., "result": {"content": [...], "isError": true}}
    let has_jsonrpc_error_object = val.get("error").is_some();
    let has_mcp_call_tool_result_is_error = val
        .get("result")
        .and_then(|r| r.get("isError"))
        .and_then(|e| e.as_bool())
        .unwrap_or(false);

    assert!(
        has_jsonrpc_error_object || has_mcp_call_tool_result_is_error,
        "Response must either contain JSON-RPC 2.0 §5.1 'error' object or MCP CallToolResult 'result.isError: true'. Response was: {}",
        resp
    );
}

/// Tests strict JSON-RPC 2.0 §5.1 error response format specified in DISPATCH.md:
/// {"jsonrpc": "2.0", "id": <exact_id>, "error": {"code": -32000, "message": "...", "data": ...}}
#[test]
fn test_mcp_error_response_strict_jsonrpc_2_0_spec_compliance() {
    let dummy_decision = HookEvaluationDecision::deny(
        "Privileged command elevation rejected",
        Some("Layer 1: SemanticCommandAst"),
        Some("Use unprivileged command"),
        25,
    );

    let id = serde_json::json!("req-test-123");
    let resp = format_mcp_error_response(&id, &dummy_decision);
    let val: serde_json::Value = serde_json::from_str(&resp).expect("valid json response");

    // DISPATCH.md requirement 3 specifies:
    // Response structure: {"jsonrpc": "2.0", "id": <exact_id>, "error": {"code": -32000, "message": "...", "data": ...}}
    assert!(
        val.get("error").is_some(),
        "DISPATCH.md requirement: MCP error response must contain 'error' object conforming to JSON-RPC 2.0 §5.1. Actual response was: {}",
        resp
    );
    assert!(
        val["error"].get("code").and_then(|c| c.as_i64()).is_some(),
        "JSON-RPC 2.0 §5.1 requires integer error code in 'error.code'"
    );
    assert!(
        val["error"]
            .get("message")
            .and_then(|m| m.as_str())
            .is_some(),
        "JSON-RPC 2.0 §5.1 requires string error message in 'error.message'"
    );
}

// ============================================================================
// 3. Wire Format Synonym Variations Across Agent Hooks
// ============================================================================

/// Tests tool name synonyms: `tool_name`, `name`, `tool` across Claude hook parser
#[test]
fn test_claude_wire_format_tool_name_synonyms() {
    let tool_name_variants = ["tool_name", "name", "tool"];

    for key in tool_name_variants {
        let mut map = serde_json::Map::new();
        map.insert(
            key.to_string(),
            serde_json::Value::String("Bash".to_string()),
        );
        let mut input = serde_json::Map::new();
        input.insert(
            "command".to_string(),
            serde_json::Value::String("sudo rm -rf /".to_string()),
        );
        map.insert("tool_input".to_string(), serde_json::Value::Object(input));

        let raw = serde_json::Value::Object(map).to_string();
        let parsed = parse_claude_request(&raw, false).expect("parse claude");

        assert_eq!(
            parsed.tool_name.as_deref(),
            Some("Bash"),
            "Claude hook must resolve tool name synonym '{}'",
            key
        );

        let decision = evaluate_hook_synchronously(&parsed);
        assert!(
            !decision.allowed,
            "Privileged command with tool synonym '{}' must be denied",
            key
        );
    }
}

/// Tests tool argument synonyms: `tool_input`, `arguments`, `args`, `parameters` across Claude hook parser
#[test]
fn test_claude_wire_format_argument_synonyms() {
    let arg_variants = ["tool_input", "arguments", "args", "parameters"];

    for key in arg_variants {
        let mut map = serde_json::Map::new();
        map.insert(
            "tool_name".to_string(),
            serde_json::Value::String("Bash".to_string()),
        );
        let mut input = serde_json::Map::new();
        input.insert(
            "command".to_string(),
            serde_json::Value::String("sudo rm -rf /".to_string()),
        );
        map.insert(key.to_string(), serde_json::Value::Object(input));

        let raw = serde_json::Value::Object(map).to_string();
        let parsed = parse_claude_request(&raw, false).expect("parse claude");

        assert_eq!(
            parsed.command.as_deref(),
            Some("sudo rm -rf /"),
            "Claude hook must resolve argument synonym '{}' and extract command",
            key
        );

        let decision = evaluate_hook_synchronously(&parsed);
        assert!(
            !decision.allowed,
            "Privileged command via argument synonym '{}' must be denied",
            key
        );
    }
}

/// Tests Cursor hook wire synonyms: tool name (`tool_name`, `name`, `tool`) and args (`arguments`, `args`, `parameters`, `tool_input`)
#[test]
fn test_cursor_wire_format_synonyms() {
    // 1. Tool name synonyms in Cursor
    let tool_variants = ["tool_name", "name", "tool"];
    for key in tool_variants {
        let mut map = serde_json::Map::new();
        map.insert(
            key.to_string(),
            serde_json::Value::String("terminal".to_string()),
        );
        map.insert(
            "command".to_string(),
            serde_json::Value::String("sudo rm -rf /".to_string()),
        );
        let raw = serde_json::Value::Object(map).to_string();

        let parsed = parse_cursor_request(&raw, "beforeShellExecution").expect("parse cursor");
        assert_eq!(
            parsed.tool_name.as_deref(),
            Some("terminal"),
            "Cursor must resolve tool name synonym '{}'",
            key
        );
    }

    // 2. Argument synonyms in Cursor
    let arg_variants = ["arguments", "args", "parameters", "tool_input"];
    for key in arg_variants {
        let mut map = serde_json::Map::new();
        let mut inner = serde_json::Map::new();
        inner.insert(
            "command".to_string(),
            serde_json::Value::String("sudo rm -rf /".to_string()),
        );
        map.insert(key.to_string(), serde_json::Value::Object(inner));
        let raw = serde_json::Value::Object(map).to_string();

        let parsed = parse_cursor_request(&raw, "beforeShellExecution").expect("parse cursor");
        assert!(
            parsed.arguments.is_some(),
            "Cursor must resolve argument synonym '{}'",
            key
        );
    }
}

/// Tests Copilot hook wire synonyms: tool name (`tool`, `tool_name`, `name`) and params (`parameters`, `arguments`, `args`, `tool_input`)
#[test]
fn test_copilot_wire_format_synonyms() {
    // 1. Tool name synonyms in Copilot
    let tool_variants = ["tool", "tool_name", "name"];
    for key in tool_variants {
        let mut map = serde_json::Map::new();
        map.insert(
            key.to_string(),
            serde_json::Value::String("terminal.execute".to_string()),
        );
        let mut p = serde_json::Map::new();
        p.insert(
            "command".to_string(),
            serde_json::Value::String("sudo rm -rf /".to_string()),
        );
        map.insert("parameters".to_string(), serde_json::Value::Object(p));
        let raw = serde_json::Value::Object(map).to_string();

        let parsed = parse_copilot_request(&raw, "preToolUse").expect("parse copilot");
        assert_eq!(
            parsed.tool_name.as_deref(),
            Some("terminal.execute"),
            "Copilot must resolve tool name synonym '{}'",
            key
        );
    }

    // 2. Parameter synonyms in Copilot
    let param_variants = ["parameters", "arguments", "args", "tool_input"];
    for key in param_variants {
        let mut map = serde_json::Map::new();
        map.insert(
            "tool".to_string(),
            serde_json::Value::String("terminal.execute".to_string()),
        );
        let mut inner = serde_json::Map::new();
        inner.insert(
            "command".to_string(),
            serde_json::Value::String("sudo rm -rf /".to_string()),
        );
        map.insert(key.to_string(), serde_json::Value::Object(inner));
        let raw = serde_json::Value::Object(map).to_string();

        let parsed = parse_copilot_request(&raw, "preToolUse").expect("parse copilot");
        assert_eq!(
            parsed.command.as_deref(),
            Some("sudo rm -rf /"),
            "Copilot must resolve parameter synonym '{}' and extract command",
            key
        );
    }
}

/// Tests OpenCode hook wire synonyms: tool name (`tool`, `tool_name`, `name`) and args (`args`, `arguments`, `parameters`, `tool_input`)
#[test]
fn test_opencode_wire_format_synonyms() {
    let arg_variants = ["args", "arguments", "parameters", "tool_input"];
    for key in arg_variants {
        let mut map = serde_json::Map::new();
        map.insert(
            "tool".to_string(),
            serde_json::Value::String("bash".to_string()),
        );
        let mut inner = serde_json::Map::new();
        inner.insert(
            "command".to_string(),
            serde_json::Value::String("sudo rm -rf /".to_string()),
        );
        map.insert(key.to_string(), serde_json::Value::Object(inner));
        let raw = serde_json::Value::Object(map).to_string();

        let parsed = parse_opencode_request(&raw).expect("parse opencode");
        assert_eq!(
            parsed.command.as_deref(),
            Some("sudo rm -rf /"),
            "OpenCode must resolve arg synonym '{}' and extract command",
            key
        );
    }
}

/// Tests MCP tools/call wire synonyms: `name` vs `tool_name` vs `tool`, and `arguments` vs `args` vs `parameters`
#[test]
fn test_mcp_wire_format_synonyms() {
    // 1. Tool name synonyms in MCP params
    let name_synonyms = ["name", "tool_name", "tool"];
    for n_key in name_synonyms {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                n_key: "bash",
                "arguments": {
                    "command": "sudo rm -rf /"
                }
            }
        })
        .to_string();

        let parsed = parse_mcp_call_request(&payload).expect("parse mcp");
        assert_eq!(
            parsed.tool_name.as_deref(),
            Some("bash"),
            "MCP must resolve tool name synonym '{}'",
            n_key
        );
    }

    // 2. Tool argument synonyms in MCP params
    let arg_synonyms = ["arguments", "args", "parameters", "tool_input"];
    for a_key in arg_synonyms {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "bash",
                a_key: {
                    "command": "sudo rm -rf /"
                }
            }
        })
        .to_string();

        let parsed = parse_mcp_call_request(&payload).expect("parse mcp");
        assert_eq!(
            parsed.command.as_deref(),
            Some("sudo rm -rf /"),
            "MCP must resolve argument synonym '{}' and extract command",
            a_key
        );

        let decision = evaluate_hook_synchronously(&parsed);
        assert!(
            !decision.allowed,
            "MCP tool call with argument synonym '{}' must be denied",
            a_key
        );
    }
}

/// Tests tool response synonyms: `tool_response`, `tool_result`, `result`, `content`, `output`
/// in post-tool evaluation to guarantee Incident A dynamic denial recording.
#[test]
fn test_tool_response_synonyms_incident_a_correlation() {
    let _guard = ADVERSARIAL_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_interceptions();
    let response_synonyms = [
        "tool_response",
        "tool_result",
        "result",
        "content",
        "output",
    ];

    for (idx, resp_key) in response_synonyms.iter().enumerate() {
        let session = format!("session-resp-synonym-{idx}");
        let mut map = serde_json::Map::new();
        map.insert(
            "tool_name".to_string(),
            serde_json::Value::String("Bash".to_string()),
        );
        let mut input = serde_json::Map::new();
        input.insert(
            "command".to_string(),
            serde_json::Value::String("sudo -n id".to_string()),
        );
        map.insert("tool_input".to_string(), serde_json::Value::Object(input));
        map.insert(
            "session_id".to_string(),
            serde_json::Value::String(session.clone()),
        );

        let mut resp_obj = serde_json::Map::new();
        resp_obj.insert("exit_code".to_string(), serde_json::json!(1));
        resp_obj.insert(
            "stderr".to_string(),
            serde_json::json!("sudo: a password is required"),
        );
        map.insert(resp_key.to_string(), serde_json::Value::Object(resp_obj));

        let raw = serde_json::Value::Object(map).to_string();
        let parsed = parse_claude_request(&raw, true).expect("parse claude post");

        assert_eq!(
            parsed.exit_code,
            Some(1),
            "Response synonym '{}' must extract exit_code",
            resp_key
        );

        let dec = evaluate_hook_synchronously(&parsed);
        assert!(dec.allowed);

        // Correlator must have recorded the denial
        assert!(
            GLOBAL_CORRELATOR.active_denial_count() > 0,
            "Correlator must record dynamic denial from response synonym '{}'",
            resp_key
        );
    }
}

/// Tests sensitive system path interception under argument synonym variations.
#[test]
fn test_sensitive_path_guard_synonym_variations() {
    let _guard = ADVERSARIAL_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_interceptions();
    let arg_keys = ["arguments", "args", "parameters", "tool_input"];
    let path_keys = [
        "path",
        "file_path",
        "filePath",
        "uri",
        "working_file",
        "editor_context",
        "file",
    ];

    for arg_key in arg_keys {
        for path_key in path_keys {
            let payload = serde_json::json!({
                "jsonrpc": "2.0",
                "id": "test-sens-1",
                "method": "tools/call",
                "params": {
                    "name": "read_file",
                    arg_key: {
                        path_key: "/etc/shadow"
                    }
                }
            })
            .to_string();

            let req = parse_mcp_call_request(&payload).expect("parse mcp");
            let decision = evaluate_hook_synchronously(&req);
            assert!(
                !decision.allowed,
                "Sensitive path /etc/shadow in arg '{}' and path key '{}' must be denied by SensitiveSystemPathGuard",
                arg_key, path_key
            );
            assert_eq!(
                decision.denied_by_layer.as_deref(),
                Some("SensitiveSystemPathGuard"),
                "Rationale must mention sensitive store for synonym '{}'",
                arg_key
            );
        }

        // Also test context_paths array in arg_key
        let payload_ctx_arr = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "test-sens-ctx-arr",
            "method": "tools/call",
            "params": {
                "name": "read_file",
                arg_key: {
                    "context_paths": ["/etc/shadow"]
                }
            }
        })
        .to_string();

        let req_ctx_arr = parse_mcp_call_request(&payload_ctx_arr).expect("parse mcp ctx arr");
        let decision_ctx_arr = evaluate_hook_synchronously(&req_ctx_arr);
        assert!(
            !decision_ctx_arr.allowed,
            "context_paths array in '{}' must be denied by SensitiveSystemPathGuard",
            arg_key
        );
        assert_eq!(
            decision_ctx_arr.denied_by_layer.as_deref(),
            Some("SensitiveSystemPathGuard")
        );
    }
}

// ============================================================================
// 4. Milestone SEC-5 Iteration 4 Wire Synonyms & Integration Verification
// ============================================================================

/// 1. Cursor: `cursor_command` attempting `sudo rm -rf /` -> must be denied with `decision.allowed == false`.
#[test]
fn test_cursor_cursor_command_synonym() {
    let _guard = ADVERSARIAL_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_interceptions();

    // 1. Single string cursor_command
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
        "Privileged command via 'cursor_command' must be denied with decision.allowed == false"
    );

    // 2. Token array cursor_command: ["sudo", "rm", "-rf", "/"]
    let payload_arr = serde_json::json!({
        "cursor_command": ["sudo", "rm", "-rf", "/"]
    })
    .to_string();

    let req_arr =
        parse_cursor_request(&payload_arr, "beforeShellExecution").expect("parse cursor array");
    assert_eq!(
        req_arr.command.as_deref(),
        Some("sudo rm -rf /"),
        "Cursor hook must extract token array command from 'cursor_command'"
    );

    let decision_arr = evaluate_hook_synchronously(&req_arr);
    assert!(
        !decision_arr.allowed,
        "Privileged token array cursor_command must be denied"
    );

    // 3. Nested in arguments
    let payload_nested = serde_json::json!({
        "arguments": {
            "cursor_command": "sudo rm -rf /"
        }
    })
    .to_string();

    let req_nested =
        parse_cursor_request(&payload_nested, "beforeShellExecution").expect("parse cursor nested");
    assert_eq!(
        req_nested.command.as_deref(),
        Some("sudo rm -rf /"),
        "Cursor hook must extract nested 'cursor_command' from arguments"
    );

    let decision_nested = evaluate_hook_synchronously(&req_nested);
    assert!(!decision_nested.allowed);
}

/// 2. Cursor: `context_paths` as array `["/etc/shadow"]` -> must be denied under `SensitiveSystemPathGuard`.
#[test]
fn test_cursor_context_paths_synonym() {
    let _guard = ADVERSARIAL_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_interceptions();

    // 1. Array of strings context_paths: ["/etc/shadow"]
    let payload_arr = serde_json::json!({
        "context_paths": ["/etc/shadow", "/home/user/code.rs"]
    })
    .to_string();

    let req_arr = parse_cursor_request(&payload_arr, "beforeReadFile").expect("parse cursor");
    assert_eq!(
        req_arr.file_path.as_deref(),
        Some("/etc/shadow"),
        "Cursor hook must extract file_path from array 'context_paths'"
    );

    let decision_arr = evaluate_hook_synchronously(&req_arr);
    assert!(
        !decision_arr.allowed,
        "Cursor context_paths targeting /etc/shadow must be denied"
    );
    assert_eq!(
        decision_arr.denied_by_layer.as_deref(),
        Some("SensitiveSystemPathGuard"),
        "Must be denied under SensitiveSystemPathGuard"
    );

    // 2. Single string context_paths
    let payload_str = serde_json::json!({
        "context_paths": "/etc/shadow"
    })
    .to_string();

    let req_str = parse_cursor_request(&payload_str, "beforeReadFile").expect("parse cursor");
    assert_eq!(
        req_str.file_path.as_deref(),
        Some("/etc/shadow"),
        "Cursor hook must extract file_path from single string 'context_paths'"
    );

    let decision_str = evaluate_hook_synchronously(&req_str);
    assert!(
        !decision_str.allowed,
        "Cursor string context_paths targeting /etc/shadow must be denied"
    );
    assert_eq!(
        decision_str.denied_by_layer.as_deref(),
        Some("SensitiveSystemPathGuard")
    );

    // 3. Nested in arguments
    let payload_nested = serde_json::json!({
        "arguments": {
            "context_paths": ["/etc/shadow"]
        }
    })
    .to_string();

    let req_nested =
        parse_cursor_request(&payload_nested, "beforeReadFile").expect("parse cursor nested");
    assert_eq!(req_nested.file_path.as_deref(), Some("/etc/shadow"));

    let decision_nested = evaluate_hook_synchronously(&req_nested);
    assert!(!decision_nested.allowed);
    assert_eq!(
        decision_nested.denied_by_layer.as_deref(),
        Some("SensitiveSystemPathGuard")
    );
}

/// 3. OpenCode: `subcommand` attempting `sudo rm -rf /` and `working_file` targeting `/etc/shadow` -> denied.
#[test]
fn test_opencode_subcommand_and_working_file_synonyms() {
    let _guard = ADVERSARIAL_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_interceptions();

    // 1. subcommand attempting privilege escalation
    let cmd_payload = serde_json::json!({
        "tool": "bash",
        "subcommand": "sudo rm -rf /"
    })
    .to_string();

    let cmd_req = parse_opencode_request(&cmd_payload).expect("parse opencode subcommand");
    assert_eq!(
        cmd_req.command.as_deref(),
        Some("sudo rm -rf /"),
        "OpenCode hook must extract command from 'subcommand'"
    );

    let cmd_decision = evaluate_hook_synchronously(&cmd_req);
    assert!(
        !cmd_decision.allowed,
        "OpenCode privileged subcommand must be denied"
    );

    // 2. working_file targeting /etc/shadow
    let file_payload = serde_json::json!({
        "tool": "read_file",
        "working_file": "/etc/shadow"
    })
    .to_string();

    let file_req = parse_opencode_request(&file_payload).expect("parse opencode working_file");
    assert_eq!(
        file_req.file_path.as_deref(),
        Some("/etc/shadow"),
        "OpenCode hook must extract file_path from 'working_file'"
    );

    let file_decision = evaluate_hook_synchronously(&file_req);
    assert!(
        !file_decision.allowed,
        "OpenCode working_file targeting /etc/shadow must be denied"
    );
    assert_eq!(
        file_decision.denied_by_layer.as_deref(),
        Some("SensitiveSystemPathGuard"),
        "Must be denied under SensitiveSystemPathGuard"
    );

    // 3. Both subcommand and working_file nested inside args
    let combined_payload = serde_json::json!({
        "tool": "bash",
        "args": {
            "subcommand": ["sudo", "cat", "/etc/shadow"],
            "working_file": "/etc/shadow"
        }
    })
    .to_string();

    let comb_req = parse_opencode_request(&combined_payload).expect("parse opencode combined");
    assert_eq!(
        comb_req.command.as_deref(),
        Some("sudo cat /etc/shadow"),
        "OpenCode hook must extract array subcommand from args"
    );
    assert_eq!(
        comb_req.file_path.as_deref(),
        Some("/etc/shadow"),
        "OpenCode hook must extract working_file from args"
    );

    let comb_decision = evaluate_hook_synchronously(&comb_req);
    assert!(!comb_decision.allowed);
}

/// 4. GitHub Copilot: `copilot_action` attempting `sudo rm -rf /` and `editor_context` targeting `/etc/shadow` -> denied.
#[test]
fn test_copilot_action_and_editor_context_synonyms() {
    let _guard = ADVERSARIAL_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_interceptions();

    // 1. copilot_action attempting privilege escalation
    let action_payload = serde_json::json!({
        "tool": "terminal.execute",
        "copilot_action": "sudo rm -rf /"
    })
    .to_string();

    let action_req =
        parse_copilot_request(&action_payload, "preToolUse").expect("parse copilot action");
    assert_eq!(
        action_req.command.as_deref(),
        Some("sudo rm -rf /"),
        "Copilot hook must extract command from 'copilot_action'"
    );

    let action_dec = evaluate_hook_synchronously(&action_req);
    assert!(
        !action_dec.allowed,
        "Copilot copilot_action attempting sudo rm -rf / must be denied"
    );

    // 2. editor_context targeting /etc/shadow
    let editor_payload = serde_json::json!({
        "tool": "editor.open",
        "editor_context": "/etc/shadow"
    })
    .to_string();

    let editor_req =
        parse_copilot_request(&editor_payload, "preToolUse").expect("parse copilot editor");
    assert_eq!(
        editor_req.file_path.as_deref(),
        Some("/etc/shadow"),
        "Copilot hook must extract file_path from 'editor_context'"
    );

    let editor_dec = evaluate_hook_synchronously(&editor_req);
    assert!(
        !editor_dec.allowed,
        "Copilot editor_context targeting /etc/shadow must be denied"
    );
    assert_eq!(
        editor_dec.denied_by_layer.as_deref(),
        Some("SensitiveSystemPathGuard"),
        "Must be denied under SensitiveSystemPathGuard"
    );

    // 3. Nested inside parameters object
    let nested_payload = serde_json::json!({
        "tool": "terminal.execute",
        "parameters": {
            "copilot_action": ["sudo", "rm", "-rf", "/"],
            "editor_context": "/etc/shadow"
        }
    })
    .to_string();

    let nested_req =
        parse_copilot_request(&nested_payload, "preToolUse").expect("parse copilot nested");
    assert_eq!(nested_req.command.as_deref(), Some("sudo rm -rf /"));
    assert_eq!(nested_req.file_path.as_deref(), Some("/etc/shadow"));

    let nested_dec = evaluate_hook_synchronously(&nested_req);
    assert!(!nested_dec.allowed);
}

/// 5. Claude Code: `tool_use_id` extracted into `session_id`.
#[test]
fn test_claude_tool_use_id_synonym() {
    let _guard = ADVERSARIAL_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_interceptions();

    // 1. PreToolUse payload with tool_use_id
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_use_id": "tool-use-claude-9999",
        "tool_input": {
            "command": "ls -la"
        }
    })
    .to_string();

    let req = parse_claude_request(&payload, false).expect("parse claude tool_use_id");
    assert_eq!(
        req.session_id.as_deref(),
        Some("tool-use-claude-9999"),
        "Claude Code hook must extract session_id from 'tool_use_id'"
    );

    // 2. PostToolUse payload with tool_use_id
    let post_payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_use_id": "tool-use-claude-9999",
        "tool_response": {
            "exit_code": 0,
            "output": "total 0"
        }
    })
    .to_string();

    let post_req =
        parse_claude_request(&post_payload, true).expect("parse claude post tool_use_id");
    assert_eq!(
        post_req.session_id.as_deref(),
        Some("tool-use-claude-9999"),
        "Claude Code post hook must extract session_id from 'tool_use_id'"
    );
}

/// 6. MCP: `tool_result` returning `exit_code: 1` and `stderr: "sudo: a password is required"`.
///
/// Post-tool execution extracts denial and records into `GLOBAL_CORRELATOR`.
#[test]
fn test_mcp_tool_result_synonym_incident_a_correlation() {
    let _guard = ADVERSARIAL_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_interceptions();

    let initial_count = GLOBAL_CORRELATOR.active_denial_count();

    // MCP post-tool execution payload with tool_result
    let raw_payload = serde_json::json!({
        "tool_name": "bash",
        "tool_use_id": "mcp-call-session-777",
        "tool_input": {
            "command": "sudo -n id"
        },
        "tool_result": {
            "exit_code": 1,
            "stderr": "sudo: a password is required"
        }
    })
    .to_string();

    // 1. Claude hook post parsing with tool_result
    let claude_req =
        parse_claude_request(&raw_payload, true).expect("parse claude post tool_result");
    assert_eq!(
        claude_req.exit_code,
        Some(1),
        "tool_result must extract exit_code"
    );
    assert_eq!(
        claude_req.stderr.as_deref(),
        Some("sudo: a password is required"),
        "tool_result must extract stderr"
    );

    let claude_dec = evaluate_hook_synchronously(&claude_req);
    assert!(
        claude_dec.allowed,
        "PostToolUse hook evaluates to allowed after recording denial"
    );
    assert!(
        GLOBAL_CORRELATOR.active_denial_count() > initial_count,
        "GLOBAL_CORRELATOR must record dynamic denial from 'tool_result'"
    );

    // 2. Cursor hook afterShellExecution with tool_result
    let cursor_payload = serde_json::json!({
        "cursor_command": "sudo -n id",
        "cursor_trace_id": "cursor-trace-123",
        "tool_result": {
            "exit_code": 1,
            "stderr": "sudo: a password is required"
        }
    })
    .to_string();

    let cursor_req =
        parse_cursor_request(&cursor_payload, "afterShellExecution").expect("parse cursor after");
    assert_eq!(cursor_req.exit_code, Some(1));
    assert_eq!(
        cursor_req.stderr.as_deref(),
        Some("sudo: a password is required")
    );
    let cursor_dec = evaluate_hook_synchronously(&cursor_req);
    assert!(cursor_dec.allowed);

    // 3. OpenCode hook after with tool_result
    let opencode_payload = serde_json::json!({
        "type": "after",
        "subcommand": "sudo -n id",
        "session_id": "opencode-session-456",
        "tool_result": {
            "exitCode": 1,
            "stderr": "sudo: a password is required"
        }
    })
    .to_string();

    let opencode_req = parse_opencode_request(&opencode_payload).expect("parse opencode after");
    assert_eq!(opencode_req.exit_code, Some(1));
    assert_eq!(
        opencode_req.stderr.as_deref(),
        Some("sudo: a password is required")
    );
    let opencode_dec = evaluate_hook_synchronously(&opencode_req);
    assert!(opencode_dec.allowed);
}

/// 7. Helper verification: Direct unit tests confirming `extract_wire_agent_id` and `extract_wire_source_agent_id`.
#[test]
fn test_wire_agent_id_and_source_agent_id_helpers() {
    // 1. extract_wire_agent_id: agent_id, agentId, agent
    let v1 = serde_json::json!({ "agent_id": "cursor-agent-42" });
    assert_eq!(
        extract_wire_agent_id(&v1),
        Some("cursor-agent-42".to_string()),
        "Must extract from 'agent_id'"
    );

    let v2 = serde_json::json!({ "agentId": "copilot-agent-99" });
    assert_eq!(
        extract_wire_agent_id(&v2),
        Some("copilot-agent-99".to_string()),
        "Must extract from 'agentId'"
    );

    let v3 = serde_json::json!({ "agent": "claude-code" });
    assert_eq!(
        extract_wire_agent_id(&v3),
        Some("claude-code".to_string()),
        "Must extract from 'agent'"
    );

    let v_empty = serde_json::json!({ "other_field": "val" });
    assert_eq!(extract_wire_agent_id(&v_empty), None);

    // 2. extract_wire_source_agent_id: source_agent_id, sourceAgentId, caller_agent_id
    let s1 = serde_json::json!({ "source_agent_id": "orchestrator-main" });
    assert_eq!(
        extract_wire_source_agent_id(&s1),
        Some("orchestrator-main".to_string()),
        "Must extract from 'source_agent_id'"
    );

    let s2 = serde_json::json!({ "sourceAgentId": "sub-orchestrator-1" });
    assert_eq!(
        extract_wire_source_agent_id(&s2),
        Some("sub-orchestrator-1".to_string()),
        "Must extract from 'sourceAgentId'"
    );

    let s3 = serde_json::json!({ "caller_agent_id": "root-caller" });
    assert_eq!(
        extract_wire_source_agent_id(&s3),
        Some("root-caller".to_string()),
        "Must extract from 'caller_agent_id'"
    );

    let s_empty = serde_json::json!({ "unrelated": 123 });
    assert_eq!(extract_wire_source_agent_id(&s_empty), None);
}

/// Additional verification: `action` command synonym variation across platforms.
#[test]
fn test_action_command_synonym_variations() {
    let _guard = ADVERSARIAL_TEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_interceptions();

    let payload = serde_json::json!({
        "action": "sudo rm -rf /"
    })
    .to_string();

    let req = parse_cursor_request(&payload, "beforeShellExecution").expect("parse cursor action");
    assert_eq!(req.command.as_deref(), Some("sudo rm -rf /"));
    let dec = evaluate_hook_synchronously(&req);
    assert!(!dec.allowed);
}
