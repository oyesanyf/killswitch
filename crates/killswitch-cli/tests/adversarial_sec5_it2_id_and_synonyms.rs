//! Adversarial Challenge SEC-5 Iteration 2:
//! MCP JSON-RPC ID Preservation, Wire Format Synonyms, and Error Formatting Compliance.
//!
//! Evaluates the deliverables of Milestone SEC-5 Iteration 2:
//! 1. JSON-RPC ID preservation across diverse types:
//!    - String IDs (UUIDs, alphanumeric, special characters)
//!    - Large integer IDs (e.g. 9007199254740991, i64::MAX)
//!    - Negative integer IDs (-42, -1, i64::MIN)
//!    - Explicit null ID ("id": null)
//!    - Missing "id" field (JSON-RPC notification behavior)
//! 2. Wire format synonym variations:
//!    - Tool name synonyms: `tool_name`, `name`, `tool`
//!    - Tool argument synonyms: `tool_input`, `arguments`, `args`, `parameters`
//!    - Tool response synonyms: `tool_response`, `result`, `content`, `output`
//! 3. MCP error response formatting compliance (JSON-RPC 2.0 §5.1):
//!    - Response structure: `{"jsonrpc": "2.0", "id": <exact_id>, "error": {"code": -32000, "message": "...", "data": ...}}`
//!    - Verify zero ID clobbering, zero fallback to static 1 or null when an ID was provided.

use killswitch_telemetry::agent_hooks::{
    clear_interceptions, evaluate_hook_synchronously, format_mcp_error_response,
    parse_claude_request, parse_copilot_request, parse_cursor_request,
    parse_mcp_call_request, parse_opencode_request, HookEvaluationDecision,
    GLOBAL_CORRELATOR,
};

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
        let resp_val: serde_json::Value = serde_json::from_str(&resp_str).expect("parse json response");
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
        let resp_val: serde_json::Value = serde_json::from_str(&resp_str).expect("parse json response");
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
    assert!(null_val["id"].is_null(), "Explicit null ID must remain null");

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
        val["error"].get("message").and_then(|m| m.as_str()).is_some(),
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
        map.insert(key.to_string(), serde_json::Value::String("Bash".to_string()));
        let mut input = serde_json::Map::new();
        input.insert("command".to_string(), serde_json::Value::String("sudo rm -rf /".to_string()));
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
        map.insert("tool_name".to_string(), serde_json::Value::String("Bash".to_string()));
        let mut input = serde_json::Map::new();
        input.insert("command".to_string(), serde_json::Value::String("sudo rm -rf /".to_string()));
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
        map.insert(key.to_string(), serde_json::Value::String("terminal".to_string()));
        map.insert("command".to_string(), serde_json::Value::String("sudo rm -rf /".to_string()));
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
        inner.insert("command".to_string(), serde_json::Value::String("sudo rm -rf /".to_string()));
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
        map.insert(key.to_string(), serde_json::Value::String("terminal.execute".to_string()));
        let mut p = serde_json::Map::new();
        p.insert("command".to_string(), serde_json::Value::String("sudo rm -rf /".to_string()));
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
        map.insert("tool".to_string(), serde_json::Value::String("terminal.execute".to_string()));
        let mut inner = serde_json::Map::new();
        inner.insert("command".to_string(), serde_json::Value::String("sudo rm -rf /".to_string()));
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
        map.insert("tool".to_string(), serde_json::Value::String("bash".to_string()));
        let mut inner = serde_json::Map::new();
        inner.insert("command".to_string(), serde_json::Value::String("sudo rm -rf /".to_string()));
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

/// Tests tool response synonyms: `tool_response`, `result`, `content`, `output`
/// in post-tool evaluation to guarantee Incident A dynamic denial recording.
#[test]
fn test_tool_response_synonyms_incident_a_correlation() {
    clear_interceptions();
    let response_synonyms = ["tool_response", "result", "content", "output"];

    for (idx, resp_key) in response_synonyms.iter().enumerate() {
        let session = format!("session-resp-synonym-{idx}");
        let mut map = serde_json::Map::new();
        map.insert("tool_name".to_string(), serde_json::Value::String("Bash".to_string()));
        let mut input = serde_json::Map::new();
        input.insert("command".to_string(), serde_json::Value::String("sudo -n id".to_string()));
        map.insert("tool_input".to_string(), serde_json::Value::Object(input));
        map.insert("session_id".to_string(), serde_json::Value::String(session.clone()));

        let mut resp_obj = serde_json::Map::new();
        resp_obj.insert("exit_code".to_string(), serde_json::json!(1));
        resp_obj.insert("stderr".to_string(), serde_json::json!("sudo: a password is required"));
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
    let arg_keys = ["arguments", "args", "parameters", "tool_input"];

    for key in arg_keys {
        // MCP tools/call with sensitive path in synonym key
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "test-sens-1",
            "method": "tools/call",
            "params": {
                "name": "read_file",
                key: {
                    "path": "/etc/shadow"
                }
            }
        })
        .to_string();

        let req = parse_mcp_call_request(&payload).expect("parse mcp");
        let decision = evaluate_hook_synchronously(&req);
        assert!(
            !decision.allowed,
            "Sensitive path /etc/shadow in synonym '{}' must be denied by SensitiveSystemPathGuard",
            key
        );
        assert!(
            decision.rationale.contains("sensitive system credential store"),
            "Rationale must mention sensitive store for synonym '{}'",
            key
        );
    }
}
