//! Empirical Adversarial Challenge SEC-5 Iteration 3 Remediation.
//!
//! Authored by Challenger SEC-5-IT3-1:
//! 1. Empirical verification of root SSH key containment and Docker control socket containment.
//! 2. Empirical verification of multi-byte UTF-8 deal context strings without slicing panics
//!    (4-byte emojis 💰, 🚀, Cyrillic characters аб, and non-ASCII currency signs €, £, ¥).
//! 3. Adversarial path fuzzing against SensitiveSystemPathGuard (dot-segments, percent encoding,
//!    device namespaces, mixed slashes, UNC shares, and NTFS ADS).

use std::sync::Mutex;

use killswitch_telemetry::agent_hooks::{
    clear_interceptions, evaluate_hook_synchronously, parse_claude_request, parse_copilot_request,
    parse_cursor_request, parse_mcp_call_request,
};
use killswitch_telemetry::semantic_dlp::{SemanticDlpEngine, SemanticEntityKind};
use killswitch_telemetry::sensitive_paths::{
    classify_sensitive_system_path, normalize_path_for_inspection, scan_for_sensitive_system_path,
    SensitiveCredentialStoreKind,
};

static CHALLENGER_IT3_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn test_empirical_root_ssh_and_docker_socket_containment() {
    let _guard = CHALLENGER_IT3_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_interceptions();

    // Adversarial targets specified in dispatch:
    // - Root SSH private keys: /root/.ssh/id_rsa, /root/.ssh/id_ed25519, ~/.ssh/id_ecdsa, /etc/ssh/ssh_host_rsa_key
    // - Additional SSH variants: ~/.ssh/id_dsa, /root/.ssh/authorized_keys, /etc/ssh/ssh_host_ed25519_key
    // - Docker control sockets: /var/run/docker.sock, /run/docker.sock, \\.\pipe\docker_engine, //./pipe/docker_engine
    let ssh_targets = [
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ed25519",
        "~/.ssh/id_ecdsa",
        "/etc/ssh/ssh_host_rsa_key",
        "/etc/ssh/ssh_host_ed25519_key",
        "~/.ssh/id_dsa",
        "/root/.ssh/authorized_keys",
    ];

    for path in ssh_targets {
        let classified = classify_sensitive_system_path(path);
        assert_eq!(
            classified,
            Some(SensitiveCredentialStoreKind::RootSshKey),
            "classify_sensitive_system_path must recognize SSH key path '{}'",
            path
        );

        // PreToolUse gate via MCP read_file
        let mcp_call = serde_json::json!({
            "jsonrpc": "2.0",
            "id": format!("mcp-ssh-{}", path),
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
            "MCP read_file '{}' must be denied by PreToolUse hook",
            path
        );
        assert_eq!(
            decision.denied_by_layer.as_deref(),
            Some("SensitiveSystemPathGuard"),
            "MCP read_file '{}' must be denied by SensitiveSystemPathGuard",
            path
        );

        // Claude Code Bash command
        let claude_call = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {
                "command": format!("cat {}", path)
            }
        })
        .to_string();
        let claude_req = parse_claude_request(&claude_call, false).expect("parse claude");
        let claude_decision = evaluate_hook_synchronously(&claude_req);
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

        // Cursor beforeReadFile
        let cursor_call = serde_json::json!({
            "file_path": path
        })
        .to_string();
        let cursor_req =
            parse_cursor_request(&cursor_call, "beforeReadFile").expect("parse cursor");
        let cursor_decision = evaluate_hook_synchronously(&cursor_req);
        assert!(
            !cursor_decision.allowed,
            "Cursor beforeReadFile '{}' must be denied",
            path
        );
        assert_eq!(
            cursor_decision.denied_by_layer.as_deref(),
            Some("SensitiveSystemPathGuard"),
            "Cursor beforeReadFile '{}' must be denied by SensitiveSystemPathGuard",
            path
        );

        // Copilot preToolUse
        let copilot_call = serde_json::json!({
            "tool": "read_file",
            "arguments": { "path": path }
        })
        .to_string();
        let copilot_req =
            parse_copilot_request(&copilot_call, "preToolUse").expect("parse copilot");
        let copilot_decision = evaluate_hook_synchronously(&copilot_req);
        assert!(
            !copilot_decision.allowed,
            "Copilot preToolUse '{}' must be denied",
            path
        );
        assert_eq!(
            copilot_decision.denied_by_layer.as_deref(),
            Some("SensitiveSystemPathGuard"),
            "Copilot preToolUse '{}' must be denied by SensitiveSystemPathGuard",
            path
        );
    }

    let docker_targets = [
        "/var/run/docker.sock",
        "/run/docker.sock",
        r"\\.\pipe\docker_engine",
        "//./pipe/docker_engine",
        r"\\?\pipe\docker_engine",
        "pipe/docker_engine",
    ];

    for path in docker_targets {
        let classified = classify_sensitive_system_path(path);
        assert_eq!(
            classified,
            Some(SensitiveCredentialStoreKind::DockerSocket),
            "classify_sensitive_system_path must recognize Docker socket path '{}'",
            path
        );

        // MCP tool call
        let mcp_call = serde_json::json!({
            "jsonrpc": "2.0",
            "id": format!("mcp-docker-{}", path),
            "method": "tools/call",
            "params": {
                "name": "connect_socket",
                "arguments": { "socket": path }
            }
        })
        .to_string();

        let req = parse_mcp_call_request(&mcp_call).expect("parse mcp");
        let decision = evaluate_hook_synchronously(&req);
        assert!(
            !decision.allowed,
            "MCP connect_socket '{}' must be denied by PreToolUse hook",
            path
        );
        assert_eq!(
            decision.denied_by_layer.as_deref(),
            Some("SensitiveSystemPathGuard"),
            "MCP connect_socket '{}' must be denied by SensitiveSystemPathGuard",
            path
        );

        // Claude Code curl unix-socket command
        let claude_call = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": {
                "command": format!("curl --unix-socket {} http://localhost/containers/json", path)
            }
        })
        .to_string();
        let claude_req = parse_claude_request(&claude_call, false).expect("parse claude");
        let claude_decision = evaluate_hook_synchronously(&claude_req);
        assert!(
            !claude_decision.allowed,
            "Claude Bash curl unix-socket '{}' must be denied by PreToolUse hook",
            path
        );
        assert_eq!(
            claude_decision.denied_by_layer.as_deref(),
            Some("SensitiveSystemPathGuard"),
            "Claude Bash curl unix-socket '{}' must be denied by SensitiveSystemPathGuard",
            path
        );
    }
}

#[test]
fn test_empirical_multibyte_utf8_deal_context_crash_freedom() {
    let _guard = CHALLENGER_IT3_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_interceptions();

    let dlp = SemanticDlpEngine::default();

    // Adversarial multi-byte UTF-8 inputs specified in dispatch:
    // - 4-byte emojis: 💰, 🚀, 🔥, 🎉, ⚠️
    // - 2-byte Cyrillic characters: аб
    // - Non-ASCII currency signs: € (3-byte), £ (2-byte), ¥ (2-byte)
    // - Valid deal contexts: "deal value", "acquisition", "valuation", "purchase price", "merger", "transaction value"
    let test_cases = [
        // 1. 4-byte emojis with deal context and currency
        (
            r#"{"valuation": "💰 $12,500,000", "counterparty": "Acme Corp"}"#,
            true,
            "Emoji 💰 followed by USD amount in compact JSON valuation",
        ),
        (
            r#"{"valuation": "🚀 $50,000,000", "status": "approved"}"#,
            true,
            "Emoji 🚀 followed by USD amount in compact JSON valuation",
        ),
        (
            "Acquisition transaction value is 💰 $15M USD for the target firm",
            true,
            "Emoji 💰 followed by $15M USD in transaction value context",
        ),
        (
            "The merger valuation is set at 🚀 $1.2B with closing next month",
            true,
            "Emoji 🚀 followed by $1.2B in merger valuation context",
        ),
        (
            "Acquisition deal value: 💰 €15,000,000 negotiated by principal",
            true,
            "Emoji 💰 followed by 3-byte Euro sign € and amount in deal value context",
        ),
        // 2. Cyrillic characters with deal context
        (
            r#"{"deal value": "аб $25,000,000", "notes": "Cyrillic prefix test"}"#,
            true,
            "Cyrillic аб prefix followed by USD amount in compact JSON deal value",
        ),
        (
            "Acquisition deal value: аб $15M USD for target portfolio",
            true,
            "Cyrillic prefix with $15M USD in acquisition deal value context",
        ),
        (
            "Merger purchase price is EUR 20M approved by the board",
            true,
            "Merger purchase price with EUR 20M",
        ),
        (
            "Acquisition valuation: аб €5,000,000 agreed by committee",
            true,
            "Cyrillic prefix followed by Euro currency symbol in acquisition valuation",
        ),
        // 3. Non-ASCII currency signs
        (
            "Acquisition purchase price is €12,500,000 in escrow",
            true,
            "3-byte Euro symbol € attached to amount in acquisition purchase price",
        ),
        (
            "Merger valuation is € 45,000,000 as agreed",
            true,
            "3-byte Euro symbol € separated from amount in merger valuation",
        ),
        (
            "Acquisition transaction value: £50M for London subsidiary",
            true,
            "2-byte Pound symbol £ attached with million multiplier in transaction value",
        ),
        (
            "Acquisition deal value: £ 100,000,000 in cash and stock",
            true,
            "2-byte Pound symbol £ separated from amount in deal value",
        ),
        (
            "Acquisition valuation: ¥500,000,000 for Tokyo operations purchase",
            true,
            "2-byte Yen symbol ¥ attached to amount in acquisition valuation",
        ),
        (
            "Acquisition purchase price: ¥ 10,000,000 agreed",
            true,
            "2-byte Yen symbol ¥ separated from amount in purchase price",
        ),
        // 4. Mixed multi-byte strings
        (
            "Acquisition deal value: 🔥💰 €25M for rapid acquisition",
            true,
            "Multi-emoji fire + bag with Euro symbol and million multiplier",
        ),
        (
            "Merger purchase price: 🎉🚀 £100M finalized",
            true,
            "Multi-emoji party + rocket with Pound symbol and million multiplier",
        ),
        (
            "Acquisition valuation: ⚠️ ¥1B subject to regulatory review",
            true,
            "Warning emoji with Yen symbol and billion multiplier",
        ),
        // 5. Zero-panic negative stress tests (random multi-byte characters without valid numbers)
        (
            "💰🚀🎉 абвгдежзийклмнопрстуфхцчшщъыьэюя €£¥ without deal context",
            false,
            "Arbitrary multi-byte characters without deal context (crash-freedom test)",
        ),
        (
            "Acquisition deal value: 💰🚀 абв without valid numbers",
            false,
            "Deal context with multi-byte characters but no numbers (crash-freedom test)",
        ),
    ];

    for (payload, should_detect, desc) in test_cases {
        // Must NEVER panic on multi-byte UTF-8 slicing
        let verdict = dlp.evaluate_verdict_fail_closed(payload);
        eprintln!(
            "[EMPIRICAL UTF8 TEST] {}: is_allow={}, entities={:?}",
            desc,
            verdict.is_allow(),
            verdict.entities()
        );

        if should_detect {
            assert!(
                !verdict.is_allow(),
                "Failed to detect deal value in test case: {} ('{}')",
                desc,
                payload
            );
            assert!(
                verdict
                    .entities()
                    .iter()
                    .any(|e| e.kind == SemanticEntityKind::DealValue),
                "Test case '{}' must detect SemanticEntityKind::DealValue",
                desc
            );
        }
    }
}

#[test]
fn test_empirical_sensitive_path_fuzzing_edge_cases() {
    let _guard = CHALLENGER_IT3_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_interceptions();

    // Adversarial path fuzzing matrix:
    // 1. Dot-segments & relative traversal
    let dot_traversals = [
        ("/etc/./shadow", SensitiveCredentialStoreKind::UnixShadow),
        ("/etc/././shadow", SensitiveCredentialStoreKind::UnixShadow),
        (
            "/etc/foo/../shadow",
            SensitiveCredentialStoreKind::UnixShadow,
        ),
        (
            "/var/tmp/../../etc/shadow",
            SensitiveCredentialStoreKind::UnixShadow,
        ),
        ("../../etc/shadow", SensitiveCredentialStoreKind::UnixShadow),
        (
            "/root/foo/../../root/.ssh/id_rsa",
            SensitiveCredentialStoreKind::RootSshKey,
        ),
        (
            "/var/run/./docker.sock",
            SensitiveCredentialStoreKind::DockerSocket,
        ),
        (
            "/var/run/../run/docker.sock",
            SensitiveCredentialStoreKind::DockerSocket,
        ),
    ];

    for (path, expected_kind) in dot_traversals {
        let classified = classify_sensitive_system_path(path);
        let normalized = normalize_path_for_inspection(path);
        assert_eq!(
            classified,
            Some(expected_kind),
            "Dot traversal '{}' (normalized: '{}') must classify as {:?}",
            path,
            normalized,
            expected_kind
        );
    }

    // 2. Percent-encoded traversal & null-byte injection
    let encoded_traversals = [
        ("%2fetc%2fshadow", SensitiveCredentialStoreKind::UnixShadow),
        ("/etc%2fshadow", SensitiveCredentialStoreKind::UnixShadow),
        (
            "..%2f..%2fetc%2fshadow",
            SensitiveCredentialStoreKind::UnixShadow,
        ),
        (
            "%2e%2e%2froot%2f%2essh%2fid_rsa",
            SensitiveCredentialStoreKind::RootSshKey,
        ),
        (
            "%2fvar%2frun%2fdocker%2esock",
            SensitiveCredentialStoreKind::DockerSocket,
        ),
        (
            "/etc/shadow%00.txt",
            SensitiveCredentialStoreKind::UnixShadow,
        ),
        (
            "/var/run/docker.sock%00",
            SensitiveCredentialStoreKind::DockerSocket,
        ),
    ];

    for (path, expected_kind) in encoded_traversals {
        let classified = classify_sensitive_system_path(path);
        let normalized = normalize_path_for_inspection(path);
        assert_eq!(
            classified,
            Some(expected_kind),
            "Encoded traversal '{}' (normalized: '{}') must classify as {:?}",
            path,
            normalized,
            expected_kind
        );
    }

    // 3. Windows device namespaces, mixed slashes, and ADS
    let windows_matrix = [
        (
            r"\\?\C:\Windows\System32\config\SAM",
            SensitiveCredentialStoreKind::WindowsSamHive,
        ),
        (
            r"\\.\C:\Windows\System32\config\SYSTEM",
            SensitiveCredentialStoreKind::WindowsSystemHive,
        ),
        (
            "//?/C:/Windows/System32/config/SECURITY",
            SensitiveCredentialStoreKind::WindowsSecurityHive,
        ),
        (r"\etc/shadow", SensitiveCredentialStoreKind::UnixShadow),
        (
            r"/root\.ssh/id_rsa",
            SensitiveCredentialStoreKind::RootSshKey,
        ),
        (
            r"\\.\pipe\docker_engine",
            SensitiveCredentialStoreKind::DockerSocket,
        ),
        (
            "//./pipe/docker_engine",
            SensitiveCredentialStoreKind::DockerSocket,
        ),
        (
            r"C:\Windows\System32\config\SAM::$DATA",
            SensitiveCredentialStoreKind::WindowsSamHive,
        ),
        (
            "/root/.ssh/id_rsa:stream",
            SensitiveCredentialStoreKind::RootSshKey,
        ),
    ];

    for (path, expected_kind) in windows_matrix {
        let classified = classify_sensitive_system_path(path);
        let normalized = normalize_path_for_inspection(path);
        assert_eq!(
            classified,
            Some(expected_kind),
            "Windows/mixed variant '{}' (normalized: '{}') must classify as {:?}",
            path,
            normalized,
            expected_kind
        );
    }

    // 4. UNC shares and administrative shares
    let unc_matrix = [
        (
            r"\\wsl$\Ubuntu\etc\shadow",
            SensitiveCredentialStoreKind::UnixShadow,
        ),
        (
            r"\\wsl.localhost\Debian\root\.ssh\id_ed25519",
            SensitiveCredentialStoreKind::RootSshKey,
        ),
        (
            r"\\localhost\c$\Windows\System32\config\SAM",
            SensitiveCredentialStoreKind::WindowsSamHive,
        ),
        (
            r"\\localhost\admin$\System32\config\SAM",
            SensitiveCredentialStoreKind::WindowsSamHive,
        ),
    ];

    for (path, expected_kind) in unc_matrix {
        let classified = classify_sensitive_system_path(path);
        let normalized = normalize_path_for_inspection(path);
        assert_eq!(
            classified,
            Some(expected_kind),
            "UNC variant '{}' (normalized: '{}') must classify as {:?}",
            path,
            normalized,
            expected_kind
        );
    }

    // 5. scan_for_sensitive_system_path embedded in command text
    let commands = [
        ("cat /etc/shadow", SensitiveCredentialStoreKind::UnixShadow),
        (
            "open('/root/.ssh/id_rsa', 'r')",
            SensitiveCredentialStoreKind::RootSshKey,
        ),
        (
            "curl --unix-socket /var/run/docker.sock http://localhost/version",
            SensitiveCredentialStoreKind::DockerSocket,
        ),
        (
            r"reg save HKLM\SAM sam.save",
            SensitiveCredentialStoreKind::WindowsSamHive,
        ),
        (
            r"reg save HKLM\SYSTEM system.save",
            SensitiveCredentialStoreKind::WindowsSystemHive,
        ),
    ];

    for (cmd, expected_kind) in commands {
        let scanned = scan_for_sensitive_system_path(cmd);
        assert!(
            scanned.is_some(),
            "scan_for_sensitive_system_path must detect target in '{}'",
            cmd
        );
        let (kind, matched) = scanned.unwrap();
        assert_eq!(
            kind, expected_kind,
            "Command '{}' matched '{}' but expected {:?}",
            cmd, matched, expected_kind
        );
    }
}

#[test]
fn test_empirical_fuzz_path_canonicalization_and_device_namespaces() {
    let _guard = CHALLENGER_IT3_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_interceptions();

    // Adversarial device namespace, mixed slashes, and complex traversal combinations
    let matrix: &[(&str, SensitiveCredentialStoreKind)] = &[
        (
            r"\\?\C:\Windows\System32\config\SAM",
            SensitiveCredentialStoreKind::WindowsSamHive,
        ),
        (
            r"\\?\C:/Windows/System32/config/SAM",
            SensitiveCredentialStoreKind::WindowsSamHive,
        ),
        (
            r"\\.\C:\Windows\System32\config\..\config\SAM",
            SensitiveCredentialStoreKind::WindowsSamHive,
        ),
        (
            r"\\?\UNC\localhost\c$\Windows\System32\config\SAM",
            SensitiveCredentialStoreKind::WindowsSamHive,
        ),
        (
            r"\\?\UNC\wsl$\Ubuntu\root\.ssh\id_rsa",
            SensitiveCredentialStoreKind::RootSshKey,
        ),
        (
            r"\\?\UNC\wsl.localhost\Debian\root\.ssh\id_ed25519",
            SensitiveCredentialStoreKind::RootSshKey,
        ),
        (
            "//?/UNC/wsl.localhost/Debian/var/run/docker.sock",
            SensitiveCredentialStoreKind::DockerSocket,
        ),
        (
            r"C:\Windows\System32\config\SAM:stream:$DATA",
            SensitiveCredentialStoreKind::WindowsSamHive,
        ),
        (
            "/etc/./ssh/../ssh/ssh_host_rsa_key",
            SensitiveCredentialStoreKind::RootSshKey,
        ),
        (
            "~/.ssh/../.ssh/id_ecdsa",
            SensitiveCredentialStoreKind::RootSshKey,
        ),
        (
            "/root/./.ssh/./id_rsa",
            SensitiveCredentialStoreKind::RootSshKey,
        ),
        (
            r"\\.\pipe\docker_engine",
            SensitiveCredentialStoreKind::DockerSocket,
        ),
        (
            "//./pipe/docker_engine",
            SensitiveCredentialStoreKind::DockerSocket,
        ),
        (
            "//?/pipe/docker_engine",
            SensitiveCredentialStoreKind::DockerSocket,
        ),
        (
            r"pipe\docker_engine",
            SensitiveCredentialStoreKind::DockerSocket,
        ),
    ];

    for (raw_path, expected_kind) in matrix {
        let classified = classify_sensitive_system_path(raw_path);
        let normalized = normalize_path_for_inspection(raw_path);
        eprintln!(
            "[CANONICALIZATION FUZZ] raw='{}', norm='{}', classified={:?}",
            raw_path, normalized, classified
        );
        assert_eq!(
            classified,
            Some(*expected_kind),
            "Fuzz path '{}' (normalized: '{}') failed to classify as {:?}",
            raw_path,
            normalized,
            expected_kind
        );

        // PreToolUse gate check
        let mcp_call = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "fuzz-check",
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": raw_path }
            }
        })
        .to_string();

        let req = parse_mcp_call_request(&mcp_call).expect("parse mcp");
        let decision = evaluate_hook_synchronously(&req);
        assert!(
            !decision.allowed,
            "Fuzz path '{}' must be denied by hook",
            raw_path
        );
        assert_eq!(
            decision.denied_by_layer.as_deref(),
            Some("SensitiveSystemPathGuard"),
            "Fuzz path '{}' must be denied by SensitiveSystemPathGuard",
            raw_path
        );
    }
}

#[test]
fn test_empirical_fuzz_multibyte_boundary_torture() {
    let _guard = CHALLENGER_IT3_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    clear_interceptions();

    let dlp = SemanticDlpEngine::default();

    // Torture payloads designed to provoke indexing panics:
    // 1. Strings composed of 1, 2, 3, and 4 byte UTF-8 sequences at token boundaries
    let multi_byte_prefixes = [
        "A",      // 1-byte
        "аб",     // 2-byte Cyrillic
        "£",      // 2-byte Pound
        "¥",      // 2-byte Yen
        "€",      // 3-byte Euro
        "日本語", // 3-byte CJK
        "한글",   // 3-byte Korean
        "💰",     // 4-byte emoji
        "🚀",     // 4-byte emoji
        "🔥",     // 4-byte emoji
        "🎉",     // 4-byte emoji
        "⚠️",     // 4-byte emoji
        "🫨",     // 4-byte emoji
        "🦹",     // 4-byte emoji
    ];

    for prefix in multi_byte_prefixes {
        // Construct payloads with prefix directly attached and separated from currency expressions
        let attached1 = format!("Acquisition deal value: {}$15,000,000", prefix);
        let attached2 = format!("Transaction value: {}€25M", prefix);
        let attached3 = format!("Valuation: {}USD 45,000,000", prefix);

        let valid_separated1 = format!("Merger valuation: {} $15,000,000", prefix);
        let valid_separated2 = format!("Purchase price: {} €25M", prefix);
        let valid_separated3 = format!("Acquisition terms: {} USD 45,000,000", prefix);

        // 1. Attached tokens must NEVER panic on multi-byte UTF-8 boundaries
        for p in [&attached1, &attached2, &attached3] {
            let _verdict = dlp.evaluate_verdict_fail_closed(p);
        }

        // 2. Properly formatted currency tokens alongside multi-byte characters must be detected and denied
        for p in [&valid_separated1, &valid_separated2, &valid_separated3] {
            let verdict = dlp.evaluate_verdict_fail_closed(p);
            assert!(
                !verdict.is_allow(),
                "Valid deal value with multi-byte prefix must be denied: '{}' (entities: {:?})",
                p,
                verdict.entities()
            );
            assert!(
                verdict
                    .entities()
                    .iter()
                    .any(|e| e.kind == SemanticEntityKind::DealValue),
                "Payload '{}' must detect SemanticEntityKind::DealValue",
                p
            );
        }
    }

    // 2. High-density emoji flood before deal value
    let emoji_flood = "💰🚀🔥🎉".repeat(500);
    let flooded_payload = format!(
        "Acquisition deal value: {} $50,000,000 in escrow",
        emoji_flood
    );
    let start = std::time::Instant::now();
    let verdict = dlp.evaluate_verdict_fail_closed(&flooded_payload);
    let elapsed = start.elapsed();
    eprintln!(
        "[EMOJI FLOOD TEST] 2000 emojis parsed in {:?}, is_allow={}, entities={:?}",
        elapsed,
        verdict.is_allow(),
        verdict.entities()
    );
    assert!(!verdict.is_allow());
    assert!(
        verdict
            .entities()
            .iter()
            .any(|e| e.kind == SemanticEntityKind::DealValue),
        "Flooded payload must detect DealValue"
    );
    assert!(
        elapsed.as_millis() < 500,
        "High-density emoji flood must evaluate within 500ms"
    );
}
