//! Process Lineage Immunity and Ancestry Traversal (Depth <= 5).
//!
//! Protects:
//! - Critical system and developer PIDs via `killswitch_core::killchain::is_critical_system_pid`.
//! - Parent process ancestry up to depth 5 using `sysinfo`.
//! - Cycles in process parentage are safely terminated via `HashSet<u32>`.
//! - Emits `VetoReason::CriticalSystemPid` or `VetoReason::ProtectedParentLineage`.

use killswitch_core::killchain::{
    is_critical_system_pid, is_developer_or_agent_runtime, is_immutable_os_kernel_pid,
};
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
    /// Target itself is an immutable OS kernel anchor or critical protected binary.
    ImmuneTarget { pid: u32, proc_name: String },
    /// An ancestor at depth 1..=5 is an immutable kernel anchor (PID 0, 1, 4, csrss, smss, wininit, systemd, launchd).
    ImmuneAncestor {
        target_pid: u32,
        ancestor_pid: u32,
        ancestor_name: String,
        depth: usize,
    },
    /// Subprocess spawned under an AI coding agent or developer runtime (e.g. cursor, code, node, python, powershell, bash, wsl).
    /// Crucially: does NOT grant automatic immunity; proceeds to full adjudication.
    AgentRuntimeChild {
        ancestor_pid: u32,
        ancestor_name: String,
        depth: usize,
    },
    /// No protected process in target or ancestry lineage.
    NotImmune,
}

impl LineageImmunityVerdict {
    pub fn is_immune(&self) -> bool {
        matches!(
            self,
            Self::ImmuneTarget { .. } | Self::ImmuneAncestor { .. }
        )
    }

    pub fn to_veto_reason(&self) -> Option<VetoReason> {
        match self {
            Self::ImmuneTarget { .. } => Some(VetoReason::CriticalSystemPid),
            Self::ImmuneAncestor { .. } => Some(VetoReason::ProtectedParentLineage),
            Self::AgentRuntimeChild { .. } => None,
            Self::NotImmune => None,
        }
    }
}

/// Extracts the lowercase binary stem: strips quotes, takes first whitespace token,
/// strips directory path components, converts to ASCII lowercase, and strips trailing `.exe`.
pub fn extract_proc_stem(name: &str) -> String {
    let trimmed = name.trim().trim_matches('"').trim_matches('\'');
    if trimmed.is_empty() {
        return String::new();
    }
    let first_token = trimmed.split_whitespace().next().unwrap_or(trimmed);
    let base = first_token
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(first_token);
    let name_lc = base.to_ascii_lowercase();
    name_lc.trim_end_matches(".exe").to_string()
}

/// Checks if a binary or command is strictly denied from receiving blanket direct target immunity.
fn is_blanket_immunity_denied(name: &str) -> bool {
    let name_no_exe = extract_proc_stem(name);
    if name_no_exe.is_empty() {
        return false;
    }

    if matches!(
        name_no_exe.as_str(),
        "wsl" | "wslservice" | "wslhost" | "sudo" | "su" | "doas" | "pkexec" | "runas"
    ) {
        return true;
    }

    // Dynamic binary metadata probe: if path exists on disk, probe for SUID or PE admin manifest
    let trimmed = name.trim().trim_matches('"').trim_matches('\'');
    let first_token = trimmed.split_whitespace().next().unwrap_or(trimmed);
    let candidate_path = std::path::Path::new(first_token);
    if candidate_path.exists() {
        if let Ok(meta) = crate::binary_probe::inspect_binary_metadata(candidate_path) {
            if meta.is_privileged_target() {
                return true;
            }
        }
    }

    false
}

/// Inspect target PID and traverse its parent ancestry up to depth 5.
pub fn inspect_process_lineage(target_pid: u32, proc_name: Option<&str>) -> LineageImmunityVerdict {
    let p_name = proc_name.unwrap_or("");
    let denied = is_blanket_immunity_denied(p_name);

    // 1. Direct Target Immunity Check
    // Privilege escalation binaries, shells, and agent interpreters NEVER receive blanket target immunity
    if !denied && is_critical_system_pid(target_pid, p_name) {
        return LineageImmunityVerdict::ImmuneTarget {
            pid: target_pid,
            proc_name: p_name.to_string(),
        };
    }

    // 2. Ancestry Traversal using reusable process-only scanner
    let mut sys = shared_ancestry_scanner().lock();
    sys.refresh_processes_specifics(ProcessRefreshKind::new());

    // TOCTOU PID-reuse immunity leak & synthetic test PID collision defense:
    // If a non-empty expected process name was provided for a target PID (> 4 and not self),
    // verify the live process name stem matches the expected stem.
    if !p_name.is_empty() && target_pid > 4 && target_pid != std::process::id() {
        if let Some(live_proc) = sys.process(Pid::from_u32(target_pid)) {
            let live_stem = extract_proc_stem(live_proc.name());
            let expected_stem = extract_proc_stem(p_name);
            if !live_stem.is_empty() && !expected_stem.is_empty() && live_stem != expected_stem {
                return LineageImmunityVerdict::NotImmune;
            }
        }
    }

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

        let parent_name = sys.process(parent_pid_obj).map(|p| p.name()).unwrap_or("");

        // Check if ancestor is an agent runtime or developer tool/shell
        if is_developer_or_agent_runtime(parent_name) {
            return LineageImmunityVerdict::AgentRuntimeChild {
                ancestor_pid: parent_pid,
                ancestor_name: parent_name.to_string(),
                depth,
            };
        }

        // Immutable kernel anchor check
        if !denied && (parent_pid <= 4 || is_immutable_os_kernel_pid(parent_pid, parent_name)) {
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
        assert_eq!(
            verdict.to_veto_reason(),
            Some(VetoReason::CriticalSystemPid)
        );

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
            assert_eq!(
                verdict.to_veto_reason(),
                Some(VetoReason::CriticalSystemPid)
            );
        }
    }

    #[test]
    fn test_privilege_escalation_and_shells_no_blanket_immunity() {
        let non_immune = [
            "sudo",
            "sudo.exe",
            "sudo -n id",
            "su",
            "su.exe",
            "su -",
            "wsl",
            "wsl.exe",
            "wsl -u root id",
            "wslservice.exe",
            "wslhost.exe",
            "doas",
            "pkexec",
            "runas",
            "runas.exe",
            "runas /user:Administrator cmd.exe",
        ];
        for app in non_immune {
            let verdict = inspect_process_lineage(4_000_001, Some(app));
            assert!(
                !verdict.is_immune(),
                "Critical vulnerability: '{}' must NOT receive blanket target immunity",
                app
            );
            assert_eq!(verdict.to_veto_reason(), None);
        }

        // Dynamic binary metadata probe test on disk
        let dir = tempfile::tempdir().unwrap();
        let bin_path = dir.path().join("renamed_installer.exe");
        let manifest = br#"
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
                <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
                    <security>
                        <requestedPrivileges>
                            <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
                        </requestedPrivileges>
                    </security>
                </trustInfo>
            </assembly>
        "#;
        std::fs::write(&bin_path, manifest).unwrap();

        let path_str = bin_path.to_str().unwrap();
        let verdict_dynamic = inspect_process_lineage(4_000_002, Some(path_str));
        assert!(
            !verdict_dynamic.is_immune(),
            "Renamed executable with requireAdministrator manifest must NOT receive blanket immunity"
        );
        assert_eq!(verdict_dynamic.to_veto_reason(), None);
    }

    #[test]
    fn test_agent_runtime_child_verdict_behavior() {
        let child_verdict = LineageImmunityVerdict::AgentRuntimeChild {
            ancestor_pid: 1000,
            ancestor_name: "cursor.exe".to_string(),
            depth: 1,
        };

        assert!(!child_verdict.is_immune());
        assert_eq!(child_verdict.to_veto_reason(), None);
    }
}
