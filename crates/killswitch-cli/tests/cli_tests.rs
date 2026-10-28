//! In-memory and diagnostic tests for `killswitch-cli` and `start.exe`.

use std::path::{Path, PathBuf};
use killswitch_cli::client::KillSwitchClient;
use killswitch_cli::loader::{UnifiedConfig, UnifiedRuntime};
use killswitch_cli::verify::SubsystemVerifier;
use killswitch_types::graph::OrchestratorMode;

#[tokio::test]
async fn test_subsystem_verifier_all_6_phases_pass() {
    let report = SubsystemVerifier::run_all().await.expect("All 7 phases must pass");
    assert!(report.all_passed, "SubsystemVerifier must report all_passed == true");
    assert_eq!(report.phases.len(), 7, "Must verify all 7 subsystem phases (including killswitch-conformal)");

    for phase in &report.phases {
        assert!(phase.passed, "Phase {} ({}) failed: {}", phase.phase_number, phase.name, phase.details);
    }
}

#[tokio::test]
async fn test_unified_runtime_boot_and_shutdown() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config = UnifiedConfig {
        host: "127.0.0.1".to_string(),
        port: 0, // OS assigned ephemeral port for testing
        mode: OrchestratorMode::Autonomous,
        db_dir: Some(temp_dir.path().to_path_buf()),
    };

    let runtime = UnifiedRuntime::boot(config).await.expect("Unified runtime boot must succeed");
    assert!(!runtime.containment_manager.get_status().isolated);
    assert_eq!(runtime.arm_registry.active_watchout_signals().await.len(), 0);
}

#[tokio::test]
async fn test_client_emergency_disarm_fallback_when_server_offline() {
    // Point client to a port where no server is running
    let client = KillSwitchClient::new("127.0.0.1", 59981);
    let disarm_res = client.disarm("test_operator", "Emergency unauthenticated disarm", None).await.unwrap();

    assert!(disarm_res.success);
    assert!(disarm_res.message.contains("Direct in-process emergency restore"));
}

fn scan_dir_recursive(dir: &Path, files: &mut Vec<PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan_dir_recursive(&path, files);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
}

#[test]
fn test_zero_os_subprocess_spawning_in_cli() {
    let cli_src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    scan_dir_recursive(&cli_src, &mut files);

    for path in &files {
        let content = std::fs::read_to_string(path).unwrap();
        assert!(!content.contains("Command::new(\"netsh"), "Forbidden netsh command in {:?}", path);
        assert!(!content.contains("Command::new(\"iptables"), "Forbidden iptables command in {:?}", path);
        assert!(!content.contains("Command::new(\"nft"), "Forbidden nft command in {:?}", path);
        assert!(!content.contains("Command::new(\"taskkill"), "Forbidden taskkill command in {:?}", path);
        assert!(!content.contains("Command::new(\"kill"), "Forbidden kill command in {:?}", path);
        assert!(!content.contains("Command::new(\"powershell"), "Forbidden powershell command in {:?}", path);
        assert!(!content.contains("Command::new(\"cmd"), "Forbidden cmd command in {:?}", path);
        assert!(!content.contains("Command::new(\"sc.exe"), "Forbidden sc.exe command in {:?}", path);
    }
    assert!(!files.is_empty(), "Must scan at least one .rs file in killswitch-cli");
}

#[tokio::test]
async fn test_cli_research_approval_gate_offline_fallback() {
    let client = KillSwitchClient::new("127.0.0.1", 59982);
    let menu = client.get_research_candidates().await.unwrap();
    assert!(menu.user_approval_required);
    assert!(!menu.candidates.is_empty());

    let approve_req = killswitch_server::types::ResearchApproveRequest {
        candidate_id: "cand-2603-02277".to_string(),
        decision: "approve".to_string(),
        operator: Some("cli_tester".to_string()),
        arxiv_id: Some("2603.02277".to_string()),
        title: Some("Zombie Agent Memory Persistence".to_string()),
        attack_vector: Some("Cross-session long-term memory persistence payload injection".to_string()),
        target_boundary: Some("agent_memory_store".to_string()),
        source_quote: Some("zombie agent cross-session memory persistence self-reinforcing payload".to_string()),
        target_crate_enhancement: Some("killswitch-telemetry".to_string()),
    };
    let res = client.approve_research_candidate(&approve_req).await.unwrap();
    assert!(res.success);
    assert_eq!(res.candidate.status, "Approved");
    assert!(res.live_probe_verified);
    assert!(res.candidate.approval_seal_blake3.is_some());
}
