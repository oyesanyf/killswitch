//! Empirical Adversarial Challenge SEC-5 Iteration 2:
//! Compact JSON DLP Tokenization and Sensitive System Path Guard.
//!
//! Evaluates defense robustness against evasion vectors:
//! 1. Compact nested JSON payloads containing secrets, cards, SSNs, NPIs, MRNs.
//! 2. Compact arrays of objects and mixed entity types.
//! 3. Compact URL query parameters with mixed delimiters.
//! 4. Deal value formatting in compact JSON and tool arguments.
//! 5. Sensitive system path bypass attempts (traversal, ADS, device, WSL2).
//! 6. Root SSH credential paths and Docker socket containment.

use killswitch_telemetry::agent_hooks::{
    clear_interceptions, evaluate_hook_synchronously, parse_claude_request, parse_cursor_request,
    parse_mcp_call_request,
};
use killswitch_telemetry::semantic_dlp::{
    RedactXStructuredValidator, SemanticDlpEngine, SemanticEntityKind,
};
use killswitch_telemetry::sensitive_paths::{
    classify_sensitive_system_path, normalize_path_for_inspection, SensitiveCredentialStoreKind,
};

#[test]
fn test_challenge_compact_nested_json_dlp_evasion() {
    clear_interceptions();
    let dlp = SemanticDlpEngine::default();

    // 1. AWS Secret Key in compact nested JSON
    let compact_aws = r#"{"auth":{"credentials":{"aws_key":"AKIAIOSFODNN7EXAMPLE"}}}"#;
    let verdict_aws = dlp.evaluate_verdict_fail_closed(compact_aws);
    assert!(
        !verdict_aws.is_allow(),
        "Compact nested JSON containing AWS key must be denied by DLP"
    );
    assert!(
        verdict_aws
            .entities()
            .iter()
            .any(|e| e.kind == SemanticEntityKind::SecretKey),
        "Detected entity must be SecretKey"
    );

    // 2. GitHub Token in compact nested JSON
    let compact_gh =
        r#"{"provider":{"github":{"pat":"ghp_111111111122222222223333333333444444"}}}"#;
    let verdict_gh = dlp.evaluate_verdict_fail_closed(compact_gh);
    assert!(
        !verdict_gh.is_allow(),
        "Compact nested JSON containing GitHub token must be denied by DLP"
    );

    // 3. Payment Card (Luhn PAN) in compact nested JSON
    let compact_pan = r#"{"order":{"checkout":{"billing":{"card":"4532015112830366"}}}}"#;
    let verdict_pan = dlp.evaluate_verdict_fail_closed(compact_pan);
    assert!(
        !verdict_pan.is_allow(),
        "Compact nested JSON containing Luhn PAN must be denied by DLP"
    );
    assert!(
        verdict_pan
            .entities()
            .iter()
            .any(|e| e.kind == SemanticEntityKind::PaymentCard),
        "Detected entity must be PaymentCard"
    );

    // 4. SSA SSN in compact nested JSON
    let compact_ssn = r#"{"employee":{"record":{"ssn":"123-45-6789"}}}"#;
    let verdict_ssn = dlp.evaluate_verdict_fail_closed(compact_ssn);
    assert!(
        !verdict_ssn.is_allow(),
        "Compact nested JSON containing SSA SSN must be denied by DLP"
    );
    assert!(
        verdict_ssn
            .entities()
            .iter()
            .any(|e| e.kind == SemanticEntityKind::PhiMedicalRecord),
        "Detected entity must be PhiMedicalRecord"
    );

    // 5. HIPAA NPI with clinical context in compact nested JSON
    assert!(RedactXStructuredValidator::npi_valid("1234567893"));
    let compact_npi =
        r#"{"clinical_findings":{"hospital":"City Clinic","provider_npi":"1234567893"}}"#;
    let verdict_npi = dlp.evaluate_verdict_fail_closed(compact_npi);
    assert!(
        !verdict_npi.is_allow(),
        "Compact nested JSON containing HIPAA NPI must be denied by DLP"
    );

    // 6. Clinical MRN in compact nested JSON
    assert!(RedactXStructuredValidator::mod11_valid("1234569"));
    let compact_mrn = r#"{"patient_intake":{"clinical_chart":{"mrn":"MRN:1234569"}}}"#;
    let verdict_mrn = dlp.evaluate_verdict_fail_closed(compact_mrn);
    assert!(
        !verdict_mrn.is_allow(),
        "Compact nested JSON containing clinical MRN must be denied by DLP"
    );

    // Verify all 6 via MCP JSON-RPC call in agent hooks
    for (name, payload_json) in [
        ("aws", compact_aws),
        ("gh", compact_gh),
        ("pan", compact_pan),
        ("ssn", compact_ssn),
        ("npi", compact_npi),
        ("mrn", compact_mrn),
    ] {
        let args: serde_json::Value = serde_json::from_str(payload_json).unwrap();
        let mcp_call = serde_json::json!({
            "jsonrpc": "2.0",
            "id": format!("test-{}", name),
            "method": "tools/call",
            "params": {
                "name": "sync_tool",
                "arguments": args
            }
        })
        .to_string();

        let req = parse_mcp_call_request(&mcp_call).expect("parse mcp call");
        let decision = evaluate_hook_synchronously(&req);
        assert!(
            !decision.allowed,
            "MCP tool call with compact nested {} must be denied by hook: {:?}",
            name, decision
        );
    }
}

#[test]
fn test_challenge_compact_arrays_and_mixed_entities() {
    clear_interceptions();
    let dlp = SemanticDlpEngine::default();

    // Compact array of objects with mixed entity types
    let compact_array =
        r#"[{"key":"AKIAIOSFODNN7EXAMPLE"},{"pan":"4532015112830366"},{"ssn":"123-45-6789"}]"#;
    let verdict = dlp.evaluate_verdict_fail_closed(compact_array);
    assert!(
        !verdict.is_allow(),
        "Compact array of objects with mixed entities must be denied by DLP"
    );
    let kinds: Vec<SemanticEntityKind> = verdict.entities().iter().map(|e| e.kind).collect();
    assert!(
        kinds.contains(&SemanticEntityKind::SecretKey),
        "Must contain SecretKey"
    );
    assert!(
        kinds.contains(&SemanticEntityKind::PaymentCard),
        "Must contain PaymentCard"
    );
    assert!(
        kinds.contains(&SemanticEntityKind::PhiMedicalRecord),
        "Must contain PhiMedicalRecord"
    );

    // MCP call with array arguments
    let args: serde_json::Value = serde_json::from_str(compact_array).unwrap();
    let mcp_call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "array-challenge",
        "method": "tools/call",
        "params": {
            "name": "batch_import",
            "arguments": { "records": args }
        }
    })
    .to_string();

    let req = parse_mcp_call_request(&mcp_call).expect("parse mcp array");
    let decision = evaluate_hook_synchronously(&req);
    assert!(
        !decision.allowed,
        "MCP tool call with compact array of mixed entities must be denied"
    );
}

#[test]
fn test_challenge_compact_url_query_parameters() {
    clear_interceptions();
    let dlp = SemanticDlpEngine::default();

    // URL query string with mixed delimiters (&, =, ?, /)
    let url = "https://internal.vault.corp/v1/auth?token=AKIAIOSFODNN7EXAMPLE&card=4532015112830366&ssn=123-45-6789";
    let verdict = dlp.evaluate_verdict_fail_closed(url);
    assert!(
        !verdict.is_allow(),
        "URL query string with mixed delimiters must be denied by DLP"
    );

    // Subprocess curl with URL query parameters in command
    let claude_call = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": format!("curl -X POST '{}'", url)
        }
    })
    .to_string();

    let req = parse_claude_request(&claude_call, false).expect("parse claude");
    let decision = evaluate_hook_synchronously(&req);
    assert!(
        !decision.allowed,
        "Curl command with sensitive URL query parameters must be denied by hook"
    );
}

#[test]
fn test_challenge_deal_value_compact_json_and_arguments() {
    clear_interceptions();
    let dlp = SemanticDlpEngine::default();

    // 1. Direct DLP evaluation of compact JSON containing deal value >= $1M
    let compact_deal = r#"{"valuation":"$12,500,000","counterparty":"Acme Corp"}"#;
    let verdict = dlp.evaluate_verdict_fail_closed(compact_deal);
    assert!(
        !verdict.is_allow(),
        "Compact JSON deal value must be restricted or denied by DLP"
    );
    assert!(
        verdict
            .entities()
            .iter()
            .any(|e| e.kind == SemanticEntityKind::DealValue),
        "Entity must be DealValue"
    );

    // 2. Large acquisition in nested compact JSON
    let compact_acq =
        r#"{"terms":{"acquisition":"Merger","purchase_price":"$45,000,000.00","currency":"USD"}}"#;
    let verdict_acq = dlp.evaluate_verdict_fail_closed(compact_acq);
    assert!(!verdict_acq.is_allow());

    // 3. Compact JSON with billions multiplier
    let compact_b = r#"{"deal_value":"$1.5B","transaction value":"approved"}"#;
    let verdict_b = dlp.evaluate_verdict_fail_closed(compact_b);
    assert!(!verdict_b.is_allow());

    // 4. MCP call passing compact deal value in arguments
    let mcp_call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "deal-test",
        "method": "tools/call",
        "params": {
            "name": "m_and_a_sync",
            "arguments": {
                "valuation": "$12,500,000",
                "counterparty": "Acme Corp"
            }
        }
    })
    .to_string();

    let req = parse_mcp_call_request(&mcp_call).expect("parse mcp deal");
    let decision = evaluate_hook_synchronously(&req);
    assert!(
        !decision.allowed,
        "MCP tool call with deal value >= $1M must be denied"
    );
}

#[test]
fn test_challenge_sensitive_path_traversal_and_windows_variations() {
    clear_interceptions();

    // 1. Path traversal variations
    let traversals = [
        "/etc/./shadow",
        "/etc/foo/../shadow",
        "\\etc\\shadow",
        "//etc//shadow",
        "/var/tmp/../../etc/shadow",
        "../../etc/shadow",
        "/etc/../etc/shadow",
    ];

    for path in traversals {
        let normalized = normalize_path_for_inspection(path);
        let classified = classify_sensitive_system_path(path);
        assert_eq!(
            classified,
            Some(SensitiveCredentialStoreKind::UnixShadow),
            "Path traversal variant '{}' (normalized: '{}') must resolve to UnixShadow",
            path,
            normalized
        );

        // PreToolUse gate via MCP
        let mcp_call = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "trav-check",
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": path }
            }
        })
        .to_string();

        let req = parse_mcp_call_request(&mcp_call).expect("parse mcp");
        let decision = evaluate_hook_synchronously(&req);
        assert!(
            !decision.allowed,
            "Traversal path '{}' must be denied by PreToolUse hook",
            path
        );
    }

    // 2. Windows ADS and device paths
    let windows_variants = [
        "C:\\Windows\\System32\\config\\SAM::$DATA",
        "\\\\?\\C:\\Windows\\System32\\config\\SAM",
        "\\\\.\\C:\\Windows\\System32\\config\\SAM",
        "/c/windows/system32/config/sam",
        "/cygdrive/c/windows/system32/config/sam",
        "/mnt/c/Windows/System32/config/SAM",
        "/mnt/c/Windows/System32/config/SAM::$DATA",
    ];

    for path in windows_variants {
        let classified = classify_sensitive_system_path(path);
        assert_eq!(
            classified,
            Some(SensitiveCredentialStoreKind::WindowsSamHive),
            "Windows variant '{}' must classify as WindowsSamHive",
            path
        );

        let mcp_call = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "win-check",
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": path }
            }
        })
        .to_string();

        let req = parse_mcp_call_request(&mcp_call).expect("parse mcp");
        let decision = evaluate_hook_synchronously(&req);
        assert!(
            !decision.allowed,
            "Windows variant path '{}' must be denied by PreToolUse hook",
            path
        );
    }
}

#[test]
fn test_challenge_root_ssh_and_docker_socket_containment() {
    clear_interceptions();

    // Adversarial targets specified in DISPATCH.md:
    // - Root SSH: /root/.ssh/id_rsa, /root/.ssh/id_ed25519, ~/.ssh/id_rsa
    // - Docker control socket: /var/run/docker.sock, /run/docker.sock
    let root_targets = [
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ed25519",
        "~/.ssh/id_rsa",
        "/var/run/docker.sock",
        "/run/docker.sock",
    ];

    for path in root_targets {
        // 1. classify_sensitive_system_path recognizes root SSH and Docker socket
        let classified = classify_sensitive_system_path(path);
        eprintln!(
            "[EMPIRICAL CONTAINMENT PROBE] classify_sensitive_system_path('{}') = {:?}",
            path, classified
        );
        assert!(
            classified.is_some(),
            "classify_sensitive_system_path must recognize '{}'",
            path
        );

        // 2. PreToolUse hook via MCP read_file tool call is DENIED by SensitiveSystemPathGuard
        let mcp_call = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "root-probe-1",
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": path }
            }
        })
        .to_string();

        let req = parse_mcp_call_request(&mcp_call).expect("parse mcp");
        let decision = evaluate_hook_synchronously(&req);
        eprintln!(
            "[EMPIRICAL CONTAINMENT PROBE] MCP read_file '{}': allowed={}, rationale='{}', layer={:?}",
            path, decision.allowed, decision.rationale, decision.denied_by_layer
        );
        assert!(
            !decision.allowed,
            "MCP read_file '{}' must be denied by PreToolUse hook",
            path
        );
        assert_eq!(
            decision.denied_by_layer.as_deref(),
            Some("SensitiveSystemPathGuard"),
            "MCP read_file '{}' must be denied by SensitiveSystemPathGuard",
            path
        );

        // 3. PreToolUse hook via Claude Code Bash cat command is DENIED by SensitiveSystemPathGuard
        let claude_call = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {
                "command": format!("cat {}", path)
            }
        })
        .to_string();

        let claude_req = parse_claude_request(&claude_call, false).expect("parse claude");
        let claude_decision = evaluate_hook_synchronously(&claude_req);
        eprintln!(
            "[EMPIRICAL CONTAINMENT PROBE] Claude Bash 'cat {}': allowed={}, rationale='{}', layer={:?}",
            path, claude_decision.allowed, claude_decision.rationale, claude_decision.denied_by_layer
        );
        assert!(
            !claude_decision.allowed,
            "Claude Bash 'cat {}' must be denied by PreToolUse hook",
            path
        );
        assert_eq!(
            claude_decision.denied_by_layer.as_deref(),
            Some("SensitiveSystemPathGuard"),
            "Claude Bash 'cat {}' must be denied by SensitiveSystemPathGuard",
            path
        );

        // 4. Cursor beforeReadFile hook is DENIED by SensitiveSystemPathGuard
        let cursor_call = serde_json::json!({
            "file_path": path
        })
        .to_string();

        let cursor_req =
            parse_cursor_request(&cursor_call, "beforeReadFile").expect("parse cursor");
        let cursor_decision = evaluate_hook_synchronously(&cursor_req);
        eprintln!(
            "[EMPIRICAL CONTAINMENT PROBE] Cursor beforeReadFile '{}': allowed={}, rationale='{}', layer={:?}",
            path, cursor_decision.allowed, cursor_decision.rationale, cursor_decision.denied_by_layer
        );
        assert!(
            !cursor_decision.allowed,
            "Cursor beforeReadFile '{}' must be denied by hook",
            path
        );
        assert_eq!(
            cursor_decision.denied_by_layer.as_deref(),
            Some("SensitiveSystemPathGuard"),
            "Cursor beforeReadFile '{}' must be denied by SensitiveSystemPathGuard",
            path
        );
    }
}
