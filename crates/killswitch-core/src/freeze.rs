//! Native Non-Destructive Process Freeze and Resume with Process Lineage Immunity.
//!
//! Windows: Dynamically resolves `NtSuspendProcess` and `NtResumeProcess` from `ntdll.dll`.
//! Linux: Delivers `libc::SIGSTOP` and `libc::SIGCONT` non-destructively.
//! Immunity: Guards system PIDs (0, 1, 4), self PID, and traverses parent ancestry up to depth 5.

use killswitch_types::{
    KillSwitchError, ProcessFreezer, ProcessIsolationMethod, ProcessIsolationState,
};
use std::collections::HashSet;
use sysinfo::{Pid, System};
use tracing::{debug, info, warn};

/// Native Process Freezer implementing `killswitch_types::ProcessFreezer`.
#[derive(Debug, Default)]
pub struct NativeProcessFreezer;

impl NativeProcessFreezer {
    pub fn new() -> Self {
        Self
    }

    /// Checks if a PID or process name is immune from freeze/tarpit containment.
    /// Delegates directly to `crate::killchain::is_critical_system_pid` to guarantee
    /// a single canonical source of truth across the entire workspace.
    #[inline]
    pub fn is_immune(&self, pid: u32, proc_name: &str) -> bool {
        crate::killchain::is_critical_system_pid(pid, proc_name)
    }

    /// Builds the set of immune PIDs:
    /// - PID 0, 1, 4
    /// - Current process ID
    /// - Up to 5 generations of parent process ancestry
    pub fn get_immune_pids(&self) -> HashSet<u32> {
        let mut immune = HashSet::new();
        immune.insert(0);
        immune.insert(1);
        immune.insert(4);

        let current_pid = std::process::id();
        immune.insert(current_pid);

        let sys = System::new_all();
        if let Some(mut proc) = sys.process(Pid::from_u32(current_pid)) {
            let mut depth = 0;
            while let Some(parent_pid) = proc.parent() {
                let p_u32 = parent_pid.as_u32();
                immune.insert(p_u32);
                depth += 1;
                if depth >= 5 {
                    break;
                }
                if let Some(parent_proc) = sys.process(parent_pid) {
                    proc = parent_proc;
                } else {
                    break;
                }
            }
        }

        immune
    }

    /// Freeze all untrusted user-space processes across the host.
    pub fn freeze_all_untrusted(&self) -> Result<Vec<ProcessIsolationState>, KillSwitchError> {
        let sys = System::new_all();
        let immune_pids = self.get_immune_pids();
        let mut frozen = Vec::new();

        for (pid_raw, proc) in sys.processes() {
            let pid = pid_raw.as_u32();
            let name = proc.name();

            if immune_pids.contains(&pid) || self.is_immune(pid, name) {
                continue;
            }

            if let Some(exe_path) = proc.exe() {
                let exe_str = exe_path.to_string_lossy();
                if self.is_immune(pid, &exe_str) {
                    continue;
                }
            }

            match self.freeze_process(pid) {
                Ok(state) => frozen.push(state),
                Err(e) => {
                    debug!("Failed to freeze PID {}: {}", pid, e);
                }
            }
        }

        info!(
            "🚨 [ProcessFreezer] Non-destructively froze {} untrusted processes.",
            frozen.len()
        );
        Ok(frozen)
    }

    /// Resume a list of frozen processes.
    pub fn resume_all(&self, pids: &[u32]) -> Vec<ProcessIsolationState> {
        let mut resumed = Vec::new();
        for &pid in pids {
            match self.resume_process(pid) {
                Ok(state) => resumed.push(state),
                Err(e) => {
                    warn!("Failed to resume PID {}: {}", pid, e);
                }
            }
        }
        info!("🟢 [ProcessFreezer] Resumed {} processes.", resumed.len());
        resumed
    }
}

impl ProcessFreezer for NativeProcessFreezer {
    fn freeze_process(&self, pid: u32) -> Result<ProcessIsolationState, KillSwitchError> {
        let proc_name = get_proc_name_by_pid(pid);

        // Guard against freezing immune processes
        if self.is_immune(pid, &proc_name) {
            return Err(KillSwitchError::ProtectedProcessImmune {
                pid,
                name: proc_name,
                reason: "Protected system, shell, or developer binary",
            });
        }

        let immune_pids = self.get_immune_pids();
        if immune_pids.contains(&pid) {
            return Err(KillSwitchError::ParentLineageImmune {
                pid,
                ancestor_pid: pid,
                ancestor_name: proc_name,
                depth: 0,
            });
        }

        #[cfg(target_os = "windows")]
        {
            freeze_process_win32(pid, &proc_name)
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            freeze_process_posix(pid, &proc_name)
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Ok(ProcessIsolationState::new_frozen(
                pid,
                proc_name,
                None,
                ProcessIsolationMethod::NtSuspendProcess,
            ))
        }
    }

    fn resume_process(&self, pid: u32) -> Result<ProcessIsolationState, KillSwitchError> {
        let proc_name = get_proc_name_by_pid(pid);

        #[cfg(target_os = "windows")]
        {
            resume_process_win32(pid, &proc_name)
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            resume_process_posix(pid, &proc_name)
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            let mut state = ProcessIsolationState::new_frozen(
                pid,
                proc_name,
                None,
                ProcessIsolationMethod::NtSuspendProcess,
            );
            state.mark_resumed();
            Ok(state)
        }
    }

    fn tarpit_process(&self, pid: u32) -> Result<ProcessIsolationState, KillSwitchError> {
        crate::tarpit::ActiveProcessTarpit::global().trap_pid_default(pid)?;
        let proc_name = get_proc_name_by_pid(pid);
        Ok(ProcessIsolationState::new_frozen(
            pid,
            proc_name,
            None,
            ProcessIsolationMethod::ThreadTarpit,
        ))
    }

    fn release_tarpit(&self, pid: u32) -> Result<ProcessIsolationState, KillSwitchError> {
        crate::tarpit::ActiveProcessTarpit::global().release_pid(pid);
        let proc_name = get_proc_name_by_pid(pid);
        let mut state = ProcessIsolationState::new_frozen(
            pid,
            proc_name,
            None,
            ProcessIsolationMethod::ThreadTarpit,
        );
        state.mark_resumed();
        Ok(state)
    }

    fn is_immune(&self, pid: u32, proc_name: &str) -> bool {
        self.is_immune(pid, proc_name)
    }
}

fn get_proc_name_by_pid(pid: u32) -> String {
    let mut s = System::new();
    let target = Pid::from_u32(pid);
    s.refresh_processes();
    s.process(target)
        .map(|p| p.name().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

// ---------------------------------------------------------------------------
// Windows Syscall Implementation (ntdll.dll NtSuspendProcess)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn freeze_process_win32(
    pid: u32,
    proc_name: &str,
) -> Result<ProcessIsolationState, KillSwitchError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SUSPEND_RESUME};

    type NtSuspendProcessFn =
        unsafe extern "system" fn(windows_sys::Win32::Foundation::HANDLE) -> i32;

    unsafe {
        let handle = OpenProcess(PROCESS_SUSPEND_RESUME, 0, pid);
        if handle.is_null() {
            let win32_code = windows_sys::Win32::Foundation::GetLastError();
            return Err(KillSwitchError::ProcessOpenFailed { pid, win32_code });
        }

        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        if ntdll.is_null() {
            CloseHandle(handle);
            return Err(KillSwitchError::NtSuspendProcessFailed {
                pid,
                ntstatus: -1,
            });
        }

        let proc = GetProcAddress(ntdll, c"NtSuspendProcess".as_ptr().cast());
        if proc.is_none() {
            CloseHandle(handle);
            return Err(KillSwitchError::NtSuspendProcessFailed {
                pid,
                ntstatus: -2,
            });
        }

        let nt_suspend: NtSuspendProcessFn = std::mem::transmute(proc.unwrap());
        let ntstatus = nt_suspend(handle);
        CloseHandle(handle);

        if ntstatus != 0 {
            return Err(KillSwitchError::NtSuspendProcessFailed { pid, ntstatus });
        }

        Ok(ProcessIsolationState::new_frozen(
            pid,
            proc_name.to_string(),
            None,
            ProcessIsolationMethod::NtSuspendProcess,
        ))
    }
}

#[cfg(target_os = "windows")]
fn resume_process_win32(
    pid: u32,
    proc_name: &str,
) -> Result<ProcessIsolationState, KillSwitchError> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SUSPEND_RESUME};

    type NtResumeProcessFn =
        unsafe extern "system" fn(windows_sys::Win32::Foundation::HANDLE) -> i32;

    unsafe {
        let handle = OpenProcess(PROCESS_SUSPEND_RESUME, 0, pid);
        if handle.is_null() {
            let win32_code = windows_sys::Win32::Foundation::GetLastError();
            return Err(KillSwitchError::ProcessOpenFailed { pid, win32_code });
        }

        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        if ntdll.is_null() {
            CloseHandle(handle);
            return Err(KillSwitchError::NtResumeProcessFailed {
                pid,
                ntstatus: -1,
            });
        }

        let proc = GetProcAddress(ntdll, c"NtResumeProcess".as_ptr().cast());
        if proc.is_none() {
            CloseHandle(handle);
            return Err(KillSwitchError::NtResumeProcessFailed {
                pid,
                ntstatus: -2,
            });
        }

        let nt_resume: NtResumeProcessFn = std::mem::transmute(proc.unwrap());
        let ntstatus = nt_resume(handle);
        CloseHandle(handle);

        if ntstatus != 0 {
            return Err(KillSwitchError::NtResumeProcessFailed { pid, ntstatus });
        }

        let mut state = ProcessIsolationState::new_frozen(
            pid,
            proc_name.to_string(),
            None,
            ProcessIsolationMethod::NtSuspendProcess,
        );
        state.mark_resumed();
        Ok(state)
    }
}

// ---------------------------------------------------------------------------
// POSIX Syscall Implementation (Linux & macOS: SIGSTOP / SIGCONT)
// ---------------------------------------------------------------------------

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn freeze_process_posix(
    pid: u32,
    proc_name: &str,
) -> Result<ProcessIsolationState, KillSwitchError> {
    let ret = unsafe { libc::kill(pid as i32, libc::SIGSTOP) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(KillSwitchError::SigStopFailed { pid, errno });
    }

    Ok(ProcessIsolationState::new_frozen(
        pid,
        proc_name.to_string(),
        None,
        ProcessIsolationMethod::SigStop,
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn resume_process_posix(
    pid: u32,
    proc_name: &str,
) -> Result<ProcessIsolationState, KillSwitchError> {
    let ret = unsafe { libc::kill(pid as i32, libc::SIGCONT) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(KillSwitchError::SigContFailed { pid, errno });
    }

    let mut state = ProcessIsolationState::new_frozen(
        pid,
        proc_name.to_string(),
        None,
        ProcessIsolationMethod::SigStop,
    );
    state.mark_resumed();
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_critical_pids_immunity() {
        let freezer = NativeProcessFreezer::new();
        assert!(freezer.is_immune(0, "System Idle Process"));
        assert!(freezer.is_immune(1, "systemd"));
        assert!(freezer.is_immune(4, "System"));
        assert!(freezer.is_immune(std::process::id(), "killswitch"));
        assert!(freezer.is_immune(99999, "explorer.exe"));
        assert!(freezer.is_immune(99998, "svchost.exe"));
        assert!(freezer.is_immune(99997, "cargo.exe"));
        assert!(freezer.is_immune(99996, "antigravity.exe"));
        assert!(freezer.is_immune(99995, "code.exe"));
        assert!(freezer.is_immune(99994, "rustc.exe"));
    }

    #[test]
    fn test_parent_lineage_immunity() {
        let freezer = NativeProcessFreezer::new();
        let immune = freezer.get_immune_pids();
        assert!(immune.contains(&std::process::id()));
        assert!(immune.contains(&0));
        assert!(immune.contains(&1));
        assert!(immune.contains(&4));
    }

    #[test]
    fn test_macos_critical_system_whitelist() {
        let freezer = NativeProcessFreezer::new();
        // The 12 mandatory macOS critical processes with various cases and paths
        let macos_procs = [
            ("launchd", 1),
            ("WindowServer", 100),
            ("loginwindow", 101),
            ("kernel_task", 0),
            ("UserEventAgent", 102),
            ("cfprefsd", 103),
            ("opendirectoryd", 104),
            ("mds", 105),
            ("Finder", 106),
            ("Dock", 107),
            ("Terminal", 108),
            ("iTerm2", 109),
            // With paths
            ("/System/Library/CoreServices/WindowServer", 200),
            ("/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", 201),
            ("/Applications/iTerm.app/Contents/MacOS/iTerm2", 202),
            ("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder", 203),
            ("/System/Library/CoreServices/Dock.app/Contents/MacOS/Dock", 204),
        ];

        for (name, pid) in macos_procs {
            assert!(
                freezer.is_immune(pid, name),
                "Expected macOS process '{}' (PID {}) to be immune",
                name,
                pid
            );
        }
    }
}
