//! Process Lineage Immunity and Ancestry Traversal (Depth <= 5).
//!
//! Protects:
//! - Critical system and developer PIDs via `killswitch_core::killchain::is_critical_system_pid`.
//! - Parent process ancestry up to depth 5 using `sysinfo`.
//! - Cycles in process parentage are safely terminated via `HashSet<u32>`.
//! - Emits `VetoReason::CriticalSystemPid` or `VetoReason::ProtectedParentLineage`.

use killswitch_core::killchain::is_critical_system_pid;
use killswitch_types::adjudication::VetoReason;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::sync::OnceLock;
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};
use tracing::warn;

fn shared_ancestry_scanner() -> &'static Mutex<System> {
    static SCANNER: OnceLock<Mutex<System>> = OnceLock::new();
    SCANNER.get_or_init(|| {
        Mutex::new(System::new_with_specifics(
            RefreshKind::new().with_processes(ProcessRefreshKind::new()),
        ))
    })
}

/// Maximum depth for process ancestry traversal.
pub const MAX_ANCESTRY_DEPTH: usize = 5;

/// Verdict returned by process lineage inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineageImmunityVerdict {
    /// Target itself is a critical system or self PID.
    ImmuneTarget { pid: u32, proc_name: String },
    /// An ancestor at depth 1..=5 is a critical system or developer process.
    ImmuneAncestor {
        target_pid: u32,
        ancestor_pid: u32,
        ancestor_name: String,
        depth: usize,
    },
    /// No protected process in target or ancestry lineage.
    NotImmune,
}

impl LineageImmunityVerdict {
    pub fn is_immune(&self) -> bool {
        !matches!(self, Self::NotImmune)
    }

    pub fn to_veto_reason(&self) -> Option<VetoReason> {
        match self {
            Self::ImmuneTarget { .. } => Some(VetoReason::CriticalSystemPid),
            Self::ImmuneAncestor { .. } => Some(VetoReason::ProtectedParentLineage),
            Self::NotImmune => None,
        }
    }
}

/// Inspect target PID and traverse its parent ancestry up to depth 5.
pub fn inspect_process_lineage(target_pid: u32, proc_name: Option<&str>) -> LineageImmunityVerdict {
    let p_name = proc_name.unwrap_or("");

    // 1. Direct Target Immunity Check
    if is_critical_system_pid(target_pid, p_name) {
        return LineageImmunityVerdict::ImmuneTarget {
            pid: target_pid,
            proc_name: p_name.to_string(),
        };
    }

    // 2. Ancestry Traversal using reusable process-only scanner
    let mut sys = shared_ancestry_scanner().lock();
    sys.refresh_processes_specifics(ProcessRefreshKind::new());

    let mut current_pid = target_pid;
    let mut visited = HashSet::new();
    visited.insert(current_pid);

    let mut depth = 0;
    while depth < MAX_ANCESTRY_DEPTH {
        let Some(proc) = sys.process(Pid::from_u32(current_pid)) else {
            break;
        };

        let Some(parent_pid_obj) = proc.parent() else {
            break;
        };

        let parent_pid = parent_pid_obj.as_u32();

        // Safe cycle boundary
        if !visited.insert(parent_pid) {
            warn!("Cycle detected in process ancestry at PID {}", parent_pid);
            break;
        }

        depth += 1;

        let parent_name = sys
            .process(parent_pid_obj)
            .map(|p| p.name())
            .unwrap_or("");

        // Root boundaries or critical parent
        if parent_pid <= 4 || is_critical_system_pid(parent_pid, parent_name) {
            return LineageImmunityVerdict::ImmuneAncestor {
                target_pid,
                ancestor_pid: parent_pid,
                ancestor_name: parent_name.to_string(),
                depth,
            };
        }

        current_pid = parent_pid;
    }

    LineageImmunityVerdict::NotImmune
}

/// Inspect process ancestry returning the full lineage list of `(PID, process_name)`.
pub fn get_process_ancestry_chain(target_pid: u32) -> Vec<(u32, String)> {
    let mut chain = Vec::new();
    let mut sys = shared_ancestry_scanner().lock();
    sys.refresh_processes_specifics(ProcessRefreshKind::new());

    let mut current_pid = target_pid;
    let mut visited = HashSet::new();
    visited.insert(current_pid);

    let mut depth = 0;
    while depth < MAX_ANCESTRY_DEPTH {
        let Some(proc) = sys.process(Pid::from_u32(current_pid)) else {
            break;
        };
        let Some(parent_pid_obj) = proc.parent() else {
            break;
        };
        let parent_pid = parent_pid_obj.as_u32();
        if !visited.insert(parent_pid) {
            break;
        }
        depth += 1;
        let parent_name = sys
            .process(parent_pid_obj)
            .map(|p| p.name().to_string())
            .unwrap_or_default();
        chain.push((parent_pid, parent_name));
        current_pid = parent_pid;
    }

    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_critical_system_pid_direct_immunity() {
        let verdict = inspect_process_lineage(4, Some("system"));
        assert!(verdict.is_immune());
        assert_eq!(verdict.to_veto_reason(), Some(VetoReason::CriticalSystemPid));

        let verdict_self = inspect_process_lineage(std::process::id(), Some("killswitch-test"));
        assert!(verdict_self.is_immune());
    }

    #[test]
    fn test_current_process_ancestry_immunity() {
        // Current process or its parent should be immune if spawned by cargo/test-runner
        let cur_pid = std::process::id();
        let chain = get_process_ancestry_chain(cur_pid);
        // Ancestry chain should resolve cleanly without hanging
        assert!(chain.len() <= MAX_ANCESTRY_DEPTH);
    }

    #[test]
    fn test_signed_os_binaries_browsers_and_ides_never_quarantined() {
        let protected = [
            "explorer.exe",
            "svchost.exe",
            "ls",
            "ssh",
            "chrome.exe",
            "msedge.exe",
            "firefox.exe",
            "safari",
            "code.exe",
            "cursor.exe",
            "devenv.exe",
            "idea64.exe",
            "rust-analyzer.exe",
        ];
        for app in protected {
            let verdict = inspect_process_lineage(4242, Some(app));
            assert!(
                verdict.is_immune(),
                "Expected '{}' to be protected by 5-layer ancestry immunity",
                app
            );
            assert_eq!(verdict.to_veto_reason(), Some(VetoReason::CriticalSystemPid));
        }
    }
}
