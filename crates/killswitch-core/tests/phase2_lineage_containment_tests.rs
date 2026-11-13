use killswitch_core::agent_registry::AgentLineageClass;
use killswitch_core::auth::OperatorAuthManager;
use killswitch_core::state_ledger::StateLedger;
use killswitch_core::{
    is_critical_system_pid, KillChainHostManager, NativeProcessFreezer, SimulatedNetworkIsolator,
    TrackedAgentTreeRegistry,
};
use killswitch_types::errors::KillSwitchError;
use killswitch_types::status::{
    ContainmentLevel, ProcessFreezer, ProcessIsolationMethod, ProcessIsolationState,
};
use parking_lot::{Mutex, RwLock};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

struct RegistryCleanupGuard(Vec<u32>);

impl Drop for RegistryCleanupGuard {
    fn drop(&mut self) {
        let reg = TrackedAgentTreeRegistry::global();
        for &pid in &self.0 {
            reg.unregister_pid(pid);
        }
    }
}

struct TempDirGuard(PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct RecordingFreezer {
    frozen: Mutex<Vec<u32>>,
    resumed: Mutex<Vec<u32>>,
}

impl ProcessFreezer for RecordingFreezer {
    fn freeze_process(&self, pid: u32) -> Result<ProcessIsolationState, KillSwitchError> {
        self.frozen.lock().push(pid);
        Ok(ProcessIsolationState::new_frozen(
            pid,
            format!("proc-{pid}"),
            None,
            ProcessIsolationMethod::NtSuspendProcess,
        ))
    }

    fn resume_process(&self, pid: u32) -> Result<ProcessIsolationState, KillSwitchError> {
        self.resumed.lock().push(pid);
        let mut s = ProcessIsolationState::new_frozen(
            pid,
            format!("proc-{pid}"),
            None,
            ProcessIsolationMethod::NtSuspendProcess,
        );
        s.mark_resumed();
        Ok(s)
    }

    fn tarpit_process(&self, pid: u32) -> Result<ProcessIsolationState, KillSwitchError> {
        self.freeze_process(pid)
    }

    fn release_tarpit(&self, pid: u32) -> Result<ProcessIsolationState, KillSwitchError> {
        self.resume_process(pid)
    }

    fn is_immune(&self, pid: u32, proc_name: &str) -> bool {
        is_critical_system_pid(pid, proc_name)
    }
}

#[tokio::test]
async fn test_phase2_killchain_freezes_entire_agent_subtree_and_spares_host_terminal() {
    let base_pid = 810_000 + (std::process::id() % 50_000) * 10;
    let host_terminal_pid = base_pid + 1;
    let uninvolved_tty_bash = base_pid + 2;
    let agent_root_pid = base_pid + 3;
    let agent_bash_pid = base_pid + 4;
    let agent_python_pid = base_pid + 5;
    let agent_curl_pid = base_pid + 6;

    let _cleanup = RegistryCleanupGuard(vec![
        agent_curl_pid,
        agent_python_pid,
        agent_bash_pid,
        agent_root_pid,
    ]);

    let reg = TrackedAgentTreeRegistry::global();
    assert!(reg.register_agent_root(agent_root_pid, "openclaw-agent"));
    assert!(reg.register_child(agent_bash_pid, agent_root_pid));
    assert!(reg.register_child(agent_python_pid, agent_bash_pid));
    assert!(reg.register_child(agent_curl_pid, agent_python_pid));

    // Tracked agent descendants lose immunity even if named after common shells/interpreters.
    assert!(!is_critical_system_pid(agent_root_pid, "openclaw-agent"));
    assert!(!is_critical_system_pid(agent_bash_pid, "bash"));
    assert!(!is_critical_system_pid(agent_python_pid, "python3"));
    assert!(!is_critical_system_pid(agent_curl_pid, "curl"));

    // Uninvolved host interactive terminals remain immune and untracked.
    assert!(is_critical_system_pid(host_terminal_pid, "wt.exe"));
    assert_eq!(
        reg.classify_pid(
            uninvolved_tty_bash,
            Some("bash"),
            &[(host_terminal_pid, uninvolved_tty_bash)]
        ),
        AgentLineageClass::Untracked
    );

    let ledger_dir = std::env::temp_dir().join(format!("ks_p2_subtree_{base_pid}"));
    let _dir_guard = TempDirGuard(ledger_dir.clone());
    let _ = std::fs::create_dir_all(&ledger_dir);

    let freezer = Arc::new(RecordingFreezer::default());
    let auth = Arc::new(OperatorAuthManager::new(None, Some(ledger_dir.clone())));
    let ledger = Arc::new(RwLock::new(
        StateLedger::open_or_init(Some(&ledger_dir)).expect("ledger init"),
    ));
    let manager = Arc::new(KillChainHostManager::new(
        Arc::new(SimulatedNetworkIsolator),
        freezer.clone(),
        auth,
        ledger,
    ));

    let status = manager
        .engage_isolation_for_target(
            "phase2_test",
            "agent exfiltration breakout via bash->python->curl",
            ContainmentLevel::ProcessFreeze,
            Some(std::process::id()),
            Some(agent_root_pid),
        )
        .await
        .expect("engage_isolation_for_target should succeed");

    assert!(status.isolated);
    let frozen: HashSet<u32> = freezer.frozen.lock().iter().copied().collect();
    assert!(
        frozen.contains(&agent_root_pid),
        "agent root PID must be frozen: {frozen:?}"
    );
    assert!(
        frozen.contains(&agent_bash_pid),
        "nested agent bash PID must be frozen: {frozen:?}"
    );
    assert!(
        frozen.contains(&agent_python_pid),
        "nested agent python PID must be frozen: {frozen:?}"
    );
    assert!(
        frozen.contains(&agent_curl_pid),
        "nested agent curl PID must be frozen: {frozen:?}"
    );
    assert!(!frozen.contains(&host_terminal_pid));
    assert!(!frozen.contains(&uninvolved_tty_bash));
    assert!(!frozen.contains(&std::process::id()));
}

#[test]
fn test_phase2_temp_staged_killswitch_masquerade_is_never_immune() {
    let freezer = NativeProcessFreezer::new();
    let spoofed = "C:\\Users\\Public\\killswitch.exe";
    assert!(!is_critical_system_pid(98_765, spoofed));
    assert!(!freezer.is_immune(98_765, spoofed));

    let tmp_spoof = "/tmp/killswitch-daemon";
    assert!(!is_critical_system_pid(98_766, tmp_spoof));
    assert!(!freezer.is_immune(98_766, tmp_spoof));
}
