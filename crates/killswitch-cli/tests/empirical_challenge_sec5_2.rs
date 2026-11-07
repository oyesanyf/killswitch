//! Empirical Adversarial Challenge SEC-5-2: Inline Synchronous Agent Hooks,
//! Incident A Evasion Vectors, and MCP Stdio JSON-RPC Proxy Stress Testing.

use killswitch_telemetry::agent_hooks::{
    clear_interceptions, evaluate_hook_synchronously, format_claude_response,
    format_copilot_response, format_cursor_response, format_mcp_error_response,
    format_opencode_response, get_recent_interceptions, parse_claude_request,
    parse_copilot_request, parse_cursor_request, parse_mcp_call_request, parse_opencode_request,
    HookEventType, NormalizedHookRequest, SupportedAgentKind, GLOBAL_CORRELATOR,
};
use std::time::Instant;

#[test]
fn test_incident_a_claude_pre_and_post_reproduction() {
    clear_interceptions();
    let session_id = "empirical-claude-session-incident-a";

    // 1. Initial attempt: Claude Code PreToolUse attempting `sudo -n id`
    let pre_payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": "sudo -n id"
        },
        "session_id": session_id
    })
    .to_string();

    let pre_req = parse_claude_request(&pre_payload, false).expect("parse claude pre");
    assert_eq!(pre_req.agent, SupportedAgentKind::Claude);
    assert_eq!(pre_req.event_type, HookEventType::PreToolUse);

    let start = Instant::now();
    let pre_decision = evaluate_hook_synchronously(&pre_req);
    let duration = start.elapsed();
    assert!(
        duration.as_millis() < 5,
        "PreToolUse evaluation must be synchronous (<5ms)"
    );
    assert!(
        !pre_decision.allowed,
        "sudo -n id must be denied in PreToolUse"
    );

    let (exit_code, stderr) = format_claude_response(&pre_decision);
    assert_eq!(
        exit_code, 2,
        "Claude Code PreToolUse denial must return exit code 2"
    );
    assert!(
        stderr.contains("Privileged command elevation rejected"),
        "Stderr must explain rejection"
    );

    // 2. Simulate PostToolUse observing dynamic auth denial from sudo
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
    assert_eq!(post_req.event_type, HookEventType::PostToolUse);
    let post_decision = evaluate_hook_synchronously(&post_req);
    assert!(
        post_decision.allowed,
        "PostToolUse records dynamic denial and allows logging"
    );
    assert!(
        GLOBAL_CORRELATOR.active_denial_count() > 0,
        "Correlator must record dynamic denial"
    );

    // 3. Immediate circumvention attempt: agent tries `wsl -u root id`
    let circumvention_payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": "wsl -u root id"
        },
        "session_id": session_id
    })
    .to_string();

    let circumvention_req =
        parse_claude_request(&circumvention_payload, false).expect("parse claude circumvention");
    let circumvention_decision = evaluate_hook_synchronously(&circumvention_req);
    assert!(
        !circumvention_decision.allowed,
        "Circumvention step wsl -u root must be synchronously BLOCKED in PreToolUse"
    );

    let (circ_code, circ_stderr) = format_claude_response(&circumvention_decision);
    assert_eq!(circ_code, 2, "Circumvention block must return exit code 2");
    assert!(
        circ_stderr.contains("Privileged") || circ_stderr.contains("Incident A"),
        "Rationale must clearly detail circumvention blocking"
    );
}

#[test]
fn test_incident_a_cursor_wire_evasion() {
    clear_interceptions();
    let session_id = "cursor-incident-a-session";

    // 1. Cursor beforeShellExecution with sudo -n
    let cursor_before = serde_json::json!({
        "command": "sudo -n id",
        "cwd": "/workspace",
        "session_id": session_id
    })
    .to_string();

    let req = parse_cursor_request(&cursor_before, "beforeShellExecution").expect("parse cursor");
    assert_eq!(req.agent, SupportedAgentKind::Cursor);
    assert_eq!(req.event_type, HookEventType::BeforeShellExecution);

    let decision = evaluate_hook_synchronously(&req);
    assert!(!decision.allowed, "Cursor sudo attempt must be denied");

    let (code, stdout) = format_cursor_response(&decision);
    assert_eq!(code, 0, "Cursor hook returns 0 exit code with json payload");
    let resp: serde_json::Value = serde_json::from_str(&stdout).expect("parse cursor stdout");
    assert_eq!(resp["permission"], "deny");
    assert!(resp["user_message"]
        .as_str()
        .unwrap()
        .contains("Containment"));

    // 2. Cursor afterShellExecution recording denial
    let cursor_after = serde_json::json!({
        "command": "sudo -n id",
        "exit_code": 1,
        "stderr": "sudo: PAM authentication failed: permission denied",
        "session_id": session_id
    })
    .to_string();

    let after_req =
        parse_cursor_request(&cursor_after, "afterShellExecution").expect("parse cursor after");
    assert_eq!(after_req.event_type, HookEventType::AfterShellExecution);
    let after_decision = evaluate_hook_synchronously(&after_req);
    assert!(after_decision.allowed);

    // 3. Cursor retry with doas id
    let cursor_retry = serde_json::json!({
        "command": "doas id",
        "session_id": session_id
    })
    .to_string();

    let retry_req =
        parse_cursor_request(&cursor_retry, "beforeShellExecution").expect("parse cursor retry");
    let retry_decision = evaluate_hook_synchronously(&retry_req);
    assert!(!retry_decision.allowed, "doas retry must be denied");
    let (_, retry_out) = format_cursor_response(&retry_decision);
    let retry_resp: serde_json::Value = serde_json::from_str(&retry_out).expect("parse retry out");
    assert_eq!(retry_resp["permission"], "deny");
}

#[test]
fn test_incident_a_evasion_variations() {
    clear_interceptions();

    // Adversarial command variants designed to evade naive string filters
    let evasion_variants = [
        // Whitespace variations
        "wsl   -u   root   id",
        "wsl\t\t-u\troot\tid",
        "  sudo   -n   id  ",
        "doas\t\tid",
        // Flag variations
        "wsl --user root id",
        "wsl --user=root id",
        "wsl -u 0 id",
        "sudo -u root whoami",
        "doas -u root cat /etc/shadow",
        "runas /user:Administrator cmd.exe",
        "runas /user:admin id",
        "runas /user:\"Administrator\" powershell.exe",
        // Nested shell invocations
        "bash -c \"wsl -u root id\"",
        "sh -c 'wsl -u root id'",
        "cmd.exe /c \"wsl -u root id\"",
        "powershell.exe -Command \"wsl -u root id\"",
        // Path-prefixed binaries
        "/mnt/c/Windows/System32/wsl.exe -u root id",
        "C:\\Windows\\System32\\wsl.exe -u root id",
        "/usr/bin/sudo -n id",
        "/usr/local/bin/doas id",
        "/usr/bin/pkexec id",
    ];

    for variant in evasion_variants {
        let req = NormalizedHookRequest {
            agent: SupportedAgentKind::Claude,
            event_type: HookEventType::PreToolUse,
            tool_name: Some("Bash".into()),
            command: Some(variant.to_string()),
            file_path: None,
            arguments: None,
            exit_code: None,
            stderr: None,
            cwd: None,
            session_id: Some("adversarial-evasion-session".into()),
            rpc_id: None,
        };

        let decision = evaluate_hook_synchronously(&req);
        assert!(
            !decision.allowed,
            "Adversarial variant must be DENIED: '{}'. Decision was: {:?}",
            variant, decision
        );
        assert!(
            decision.denied_by_layer.is_some(),
            "Denied layer must be identified for: '{}'",
            variant
        );
    }
}

#[test]
fn test_mcp_json_rpc_proxy_stress_and_malformed() {
    // Malformed JSON-RPC payloads that an adversary or corrupted network pipe might send
    let malformed_payloads = [
        "",
        "   ",
        "not json at all",
        "{invalid json",
        "{\"jsonrpc\": \"2.0\", \"method\": }",
        "12345",
        "true",
        "[\"array\", \"instead\", \"of\", \"object\"]",
        "\"raw string\"",
        "null",
        // Valid JSON but not a tools/call method
        "{\"jsonrpc\": \"2.0\", \"method\": \"initialize\", \"id\": 1}",
        "{\"jsonrpc\": \"2.0\", \"method\": \"tools/list\", \"id\": 2}",
        "{\"jsonrpc\": \"2.0\", \"method\": 999, \"id\": 3}",
        "{\"jsonrpc\": \"2.0\", \"id\": 4}",
    ];

    for malformed in malformed_payloads {
        let res = parse_mcp_call_request(malformed);
        // All non-tools/call and malformed payloads must return Err gracefully without panic
        assert!(
            res.is_err(),
            "Malformed or non-tools/call payload should return Err: '{}'",
            malformed
        );
    }

    // Edge cases: tools/call with unexpected param structures
    let unexpected_params = [
        // params is null
        "{\"jsonrpc\": \"2.0\", \"method\": \"tools/call\", \"id\": 10, \"params\": null}",
        // params is a number
        "{\"jsonrpc\": \"2.0\", \"method\": \"tools/call\", \"id\": 11, \"params\": 42}",
        // params is a string
        "{\"jsonrpc\": \"2.0\", \"method\": \"tools/call\", \"id\": 12, \"params\": \"str\"}",
        // arguments is a string
        "{\"jsonrpc\": \"2.0\", \"method\": \"tools/call\", \"id\": 13, \"params\": {\"name\": \"run\", \"arguments\": \"string\"}}",
        // arguments is an array
        "{\"jsonrpc\": \"2.0\", \"method\": \"tools/call\", \"id\": 14, \"params\": {\"name\": \"run\", \"arguments\": [1, 2, 3]}}",
    ];

    for case in unexpected_params {
        let parsed = parse_mcp_call_request(case);
        assert!(
            parsed.is_ok(),
            "Parser should handle non-standard params gracefully: {}",
            case
        );
        let req = parsed.unwrap();
        // Evaluating should not panic
        let decision = evaluate_hook_synchronously(&req);
        // Default execution without privileged commands is allowed or denied safely
        assert!(decision.execution_duration_us < 50_000);
    }
}

#[test]
fn test_mcp_json_rpc_massive_payload_stress() {
    // 1. Construct massive >4.5MB benign payload
    let large_text = "A".repeat(4 * 1024 * 1024 + 512 * 1024); // 4.5 MB
    let massive_json = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "massive-req-1",
        "method": "tools/call",
        "params": {
            "name": "data_processor",
            "arguments": {
                "blob": large_text
            }
        }
    })
    .to_string();

    assert!(massive_json.len() > 4 * 1024 * 1024);

    let start = Instant::now();
    let parsed = parse_mcp_call_request(&massive_json).expect("parse massive MCP request");
    let parse_duration = start.elapsed();
    assert!(
        parse_duration.as_millis() < 500,
        "Massive parse must finish within 500ms"
    );

    let eval_start = Instant::now();
    let decision = evaluate_hook_synchronously(&parsed);
    let eval_duration = eval_start.elapsed();
    assert!(
        eval_duration.as_millis() < 500,
        "Massive eval must finish within 500ms"
    );
    assert!(decision.allowed, "Clean large text should be allowed");

    // 2. Construct massive >4.5MB payload containing sensitive PHI/SSN entity
    let mut sensitive_blob = "B".repeat(2 * 1024 * 1024);
    sensitive_blob.push_str(" CONFIDENTIAL PATIENT MEDICAL SSN 123-45-6789 WITH DIAGNOSIS ");
    sensitive_blob.push_str(&"C".repeat(2 * 1024 * 1024));

    let sensitive_json = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "massive-sensitive-1",
        "method": "tools/call",
        "params": {
            "name": "data_processor",
            "arguments": {
                "blob": sensitive_blob
            }
        }
    })
    .to_string();

    let sensitive_parsed =
        parse_mcp_call_request(&sensitive_json).expect("parse sensitive massive MCP");
    let sensitive_decision = evaluate_hook_synchronously(&sensitive_parsed);
    assert!(
        !sensitive_decision.allowed,
        "Massive payload with PHI/SSN must be DENIED by DLP"
    );
    assert_eq!(
        sensitive_decision.denied_by_layer.as_deref(),
        Some("Layer 3: SemanticDlpEngine")
    );
}

#[test]
fn test_mcp_unauthorized_tool_calls_and_error_formatting() {
    let unauthorized_calls = [
        ("bash", serde_json::json!({"command": "sudo rm -rf /"})),
        (
            "bash",
            serde_json::json!({"command": "wsl -u root cat /etc/shadow"}),
        ),
        ("read_file", serde_json::json!({"path": "/etc/shadow"})),
        (
            "read_file",
            serde_json::json!({"path": "/workspace/confidential_payroll.xlsx", "command": "cat /workspace/confidential_payroll.xlsx"}),
        ),
        (
            "auth_tool",
            serde_json::json!({"command": "aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE"}),
        ),
        (
            "patient_query",
            serde_json::json!({"query": "SELECT * FROM patients WHERE ssn = '123-45-6789' and diagnosis='severe'"}),
        ),
        (
            "m_and_a_wire",
            serde_json::json!({"deal": "Acquisition contract value is $250,000,000.00 USD"}),
        ),
    ];

    for (tool_name, args) in unauthorized_calls {
        let mcp_call = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 999,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": args
            }
        })
        .to_string();

        let req = parse_mcp_call_request(&mcp_call).expect("parse mcp call");
        let decision = evaluate_hook_synchronously(&req);
        assert!(
            !decision.allowed,
            "Unauthorized tool call must be denied: {:?}",
            args
        );

        // Format error response
        let err_json = format_mcp_error_response(&serde_json::json!(999), &decision);
        let val: serde_json::Value = serde_json::from_str(&err_json).expect("parse err json");
        assert_eq!(val["jsonrpc"], "2.0");
        assert_eq!(val["id"], 999);
        assert_eq!(val["result"]["isError"], true);
        let text = val["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("KillSwitch Policy Violation"));

        // Verify other agent wire formatters with this denial
        let (_, copilot_out) = format_copilot_response(&decision);
        let copilot_val: serde_json::Value = serde_json::from_str(&copilot_out).unwrap();
        assert_eq!(copilot_val["permissionDecision"], "deny");

        let (_, opencode_out) = format_opencode_response(&decision);
        let opencode_val: serde_json::Value = serde_json::from_str(&opencode_out).unwrap();
        assert_eq!(opencode_val["allow"], false);
    }

    // Test various ID types in MCP error formatting
    let test_ids = [
        serde_json::json!(42),
        serde_json::json!("req-uuid-1234"),
        serde_json::Value::Null,
    ];

    for id in test_ids {
        let dummy_decision = killswitch_telemetry::agent_hooks::HookEvaluationDecision::deny(
            "Access Denied",
            Some("Layer 1"),
            None,
            12,
        );
        let err_json = format_mcp_error_response(&id, &dummy_decision);
        let val: serde_json::Value = serde_json::from_str(&err_json).unwrap();
        assert_eq!(val["id"], id);
        assert_eq!(val["result"]["isError"], true);
    }
}

#[test]
fn test_wire_format_fuzzing_resilience() {
    // Fuzz inputs with strange UTF-8, null bytes, numbers where strings expected
    let fuzz_cases = [
        "",
        "{}",
        "null",
        "{\"tool_name\": 12345}",
        "{\"tool_input\": false}",
        "{\"tool_input\": {\"command\": [1, 2, 3]}}",
        "{\"tool_response\": \"not an object\"}",
        "{\"session_id\": null}",
        "{\"command\": 99999, \"cwd\": true}",
        "{\"tool\": {}, \"parameters\": null}",
        "{\"type\": 1234, \"args\": \"invalid\"}",
        "{\"command\": \"\x00\x07\x1b\x1f\0\"}",
        "{\"command\": \"\u{fffd}\u{ffff}\"}",
    ];

    for case in fuzz_cases {
        // Claude fuzz
        if let Ok(req) = parse_claude_request(case, false) {
            let _ = evaluate_hook_synchronously(&req);
        }
        if let Ok(req) = parse_claude_request(case, true) {
            let _ = evaluate_hook_synchronously(&req);
        }

        // Cursor fuzz
        if let Ok(req) = parse_cursor_request(case, "beforeShellExecution") {
            let _ = evaluate_hook_synchronously(&req);
        }

        // Copilot fuzz
        if let Ok(req) = parse_copilot_request(case, "preToolUse") {
            let _ = evaluate_hook_synchronously(&req);
        }

        // OpenCode fuzz
        if let Ok(req) = parse_opencode_request(case) {
            let _ = evaluate_hook_synchronously(&req);
        }

        // MCP fuzz
        if let Ok(req) = parse_mcp_call_request(case) {
            let _ = evaluate_hook_synchronously(&req);
        }
    }
}

#[test]
fn test_zero_latency_synchronous_timing() {
    clear_interceptions();

    let req = NormalizedHookRequest {
        agent: SupportedAgentKind::Claude,
        event_type: HookEventType::PreToolUse,
        tool_name: Some("Bash".into()),
        command: Some("git status".into()),
        file_path: None,
        arguments: None,
        exit_code: None,
        stderr: None,
        cwd: None,
        session_id: Some("perf-session".into()),
        rpc_id: None,
    };

    let iterations = 1000;
    let start = Instant::now();
    for _ in 0..iterations {
        let decision = evaluate_hook_synchronously(&req);
        assert!(decision.allowed);
    }
    let total_elapsed = start.elapsed();
    let avg_us = total_elapsed.as_micros() as f64 / iterations as f64;

    // Average execution duration must be sub-millisecond (< 1000us)
    assert!(
        avg_us < 1000.0,
        "Average hook evaluation must be <1ms, actual: {:.2}us",
        avg_us
    );

    // Verify recent interceptions buffer reflects evaluations
    let recent = get_recent_interceptions(10);
    assert_eq!(recent.len(), 10);
}

#[test]
fn test_compact_json_dlp_evasion_finding() {
    // Demonstrates empirical finding:
    // When a tool call contains a secret token or SSN inside compact JSON arguments,
    // e.g. {"token": "AKIAIOSFODNN7EXAMPLE"}, `payload.split_whitespace()` treats the entire
    // JSON object as a single token `{"token":"AKIAIOSFODNN7EXAMPLE"}`. Because `trim_matches`
    // in `detect_secret_keys` does not strip `{` or `}`, the token begins with `{"token` rather
    // than `AKIA`, causing the secret token to evade DLP detection unless accompanied by whitespace.
    let mcp_call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 100,
        "method": "tools/call",
        "params": {
            "name": "login",
            "arguments": {
                "token": "AKIAIOSFODNN7EXAMPLE"
            }
        }
    })
    .to_string();

    let req = parse_mcp_call_request(&mcp_call).expect("parse mcp call");
    let decision = evaluate_hook_synchronously(&req);
    // Remediation verified: Compact JSON argument tokenization triggers DLP denial
    assert!(
        !decision.allowed,
        "Compact JSON secret key successfully blocked by DLP"
    );
    assert_eq!(
        decision.denied_by_layer.as_deref(),
        Some("Layer 3: SemanticDlpEngine")
    );
}
