//! Integration tests for Breakout Defense, Mathematical SSRF, and Safe Path Sandboxing (Feature 21)

use std::path::Path;
use killswitch_telemetry::octopus::breakout::{
    validate_egress_url, validate_sandbox_path, BreakoutDefenseCoordinator,
};
use killswitch_types::KillSwitchError;

#[test]
fn test_t1_f21_01_4_category_breakout_defense() {
    let coordinator = BreakoutDefenseCoordinator::new();

    // 1. Technical Breakout: Docker socket access
    let tech_eval = coordinator.evaluate_action("connect", "/var/run/docker.sock", "");
    assert!(!tech_eval.is_clean);
    assert!(!tech_eval.technical.is_clean);

    // 2. Operational Containment: API key leak
    let oper_eval = coordinator.evaluate_action(
        "exec",
        "bash",
        "export OPENAI_API_KEY=sk-proj-12345678901234567890",
    );
    assert!(!oper_eval.is_clean);
    assert!(!oper_eval.operational.is_clean);

    // 3. Behavioral Breakout: Route table probe
    let behav_eval = coordinator.evaluate_action("exec", "cmd.exe", "cmd.exe /c route print");
    assert!(!behav_eval.is_clean);
    assert!(!behav_eval.behavioral.is_clean);

    // 4. Data Breakout: Credential dumping probe
    let data_eval = coordinator.evaluate_action("exec", "procdump.exe", "-ma lsass.exe lsass.dmp");
    assert!(!data_eval.is_clean);
    assert!(!data_eval.data.is_clean);

    // Clean action passes
    let clean_eval = coordinator.evaluate_action("read", "local_scratchpad/doc.txt", "");
    assert!(clean_eval.is_clean);
}

#[test]
fn test_t1_f21_02_mathematical_ssrf_blocking() {
    // Cloud metadata
    let res_meta = validate_egress_url("http://169.254.169.254/latest/meta-data", false);
    assert!(matches!(res_meta, Err(KillSwitchError::SsrfBlocked { .. })));

    // RFC 1918 Private ranges
    assert!(validate_egress_url("http://10.0.0.1:8080/internal", false).is_err());
    assert!(validate_egress_url("http://192.168.1.1/admin", false).is_err());
    assert!(validate_egress_url("http://172.16.0.1/api", false).is_err());

    // CGNAT
    assert!(validate_egress_url("http://100.64.0.1/service", false).is_err());

    // Loopback blocked by default
    assert!(validate_egress_url("http://127.0.0.1:8080/test", false).is_err());
    assert!(validate_egress_url("http://localhost:8080/test", false).is_err());
    assert!(validate_egress_url("http://[::1]:8080/test", false).is_err());

    // Non-standard decimal, hex, shortened IPs blocked
    assert!(validate_egress_url("http://2130706433/", false).is_err());
    assert!(validate_egress_url("http://0x7f000001/", false).is_err());
    assert!(validate_egress_url("http://127.1/", false).is_err());

    // IPv6 ULA
    assert!(validate_egress_url("http://[fc00::1]/admin", false).is_err());
}

#[test]
fn test_t1_f21_03_ssrf_local_inference_allowance() {
    // When allow_local_inference is true, Ollama port 11434 and KillSwitch port 3030 pass
    assert!(validate_egress_url("http://127.0.0.1:11434/api/tags", true).is_ok());
    assert!(validate_egress_url("http://127.0.0.1:3030/status", true).is_ok());
    assert!(validate_egress_url("http://localhost:11434/api/generate", true).is_ok());

    // Non-inference loopback ports still blocked
    assert!(validate_egress_url("http://127.0.0.1:22/ssh", true).is_err());
    assert!(validate_egress_url("http://127.0.0.1:9090/metrics", true).is_err());

    // Cloud metadata is NEVER allowed, even with allow_local_inference = true
    assert!(validate_egress_url("http://169.254.169.254/latest", true).is_err());
}

#[test]
fn test_t1_f21_04_safe_path_join_traversal_blocking() {
    let sandbox = Path::new("C:\\Sandbox\\AgentWorkspace");

    // Traversal attempts
    assert!(validate_sandbox_path("../../etc/passwd", sandbox).is_err());
    assert!(validate_sandbox_path("..\\..\\Windows\\System32\\cmd.exe", sandbox).is_err());
    assert!(validate_sandbox_path("%2e%2e/secret", sandbox).is_err());

    // Alternate Data Streams (ADS)
    assert!(validate_sandbox_path("file.txt:hidden.exe", sandbox).is_err());

    // UNC / Windows Device Namespaces
    assert!(validate_sandbox_path(r"\\attacker\share\payload", sandbox).is_err());
    assert!(validate_sandbox_path(r"\\.\pipe\docker_engine", sandbox).is_err());
    assert!(validate_sandbox_path("//attacker/share", sandbox).is_err());

    // DOS Reserved Device Names
    assert!(validate_sandbox_path("CON", sandbox).is_err());
    assert!(validate_sandbox_path("NUL", sandbox).is_err());
    assert!(validate_sandbox_path("COM1", sandbox).is_err());

    // Valid relative path succeeds
    let valid = validate_sandbox_path("scratchpad/document.txt", sandbox);
    assert!(valid.is_ok());
    let joined = valid.unwrap();
    assert!(joined.starts_with(sandbox));
}
