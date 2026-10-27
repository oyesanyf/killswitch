//! Active Process Tarpit (Throttling and Asymmetric Containment).
//!
//! Subdues suspect processes by cycling them through asymmetric suspend and resume windows:
//! - Suspends execution for 25-50ms (default 30ms).
//! - Briefly resumes execution for 8ms observation burst to record telemetry without allowing harm.
//! - Cleanly balances thread suspend counts and closes all handles upon disarm.

use dashmap::DashMap;
use killswitch_types::KillSwitchError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tracing::{debug, info};

static GLOBAL_TARPIT: OnceLock<ActiveProcessTarpit> = OnceLock::new();

/// Active Process Tarpit Manager.
#[derive(Clone)]
pub struct ActiveProcessTarpit {
    active_traps: Arc<DashMap<u32, Arc<AtomicBool>>>,
}

impl Default for ActiveProcessTarpit {
    fn default() -> Self {
        Self::new()
    }
}

impl ActiveProcessTarpit {
    pub fn new() -> Self {
        Self {
            active_traps: Arc::new(DashMap::new()),
        }
    }

    /// Access the process-wide singleton tarpit instance.
    pub fn global() -> &'static Self {
        GLOBAL_TARPIT.get_or_init(Self::new)
    }

    /// Checks if a PID is actively trapped.
    pub fn is_trapped(&self, pid: u32) -> bool {
        self.active_traps
            .get(&pid)
            .map(|flag| flag.load(Ordering::Relaxed))
            .unwrap_or(false)
    }

    /// Traps a PID with default parameters (30ms suspend, 8ms burst, 30min ceiling).
    pub fn trap_pid_default(&self, pid: u32) -> Result<(), KillSwitchError> {
        self.trap_pid(
            pid,
            Duration::from_millis(30),
            Duration::from_millis(8),
            Duration::from_secs(1800),
        )
    }

    /// Releases a trapped process from the tarpit immediately.
    pub fn release_pid(&self, pid: u32) {
        if let Some((_, flag)) = self.active_traps.remove(&pid) {
            flag.store(false, Ordering::SeqCst);
            info!("🟢 [ActiveProcessTarpit] Released PID {} from tarpit.", pid);
        }
    }

    /// Releases all active traps during shutdown or emergency recovery.
    pub fn release_all(&self) {
        let pids: Vec<u32> = self.active_traps.iter().map(|entry| *entry.key()).collect();
        for pid in pids {
            self.release_pid(pid);
        }
    }

    /// Initiates asymmetric duty cycle trapping on target PID.
    pub fn trap_pid(
        &self,
        pid: u32,
        suspend_interval: Duration,
        burst_interval: Duration,
        max_duration: Duration,
    ) -> Result<(), KillSwitchError> {
        if pid <= 4 || pid == std::process::id() {
            return Err(KillSwitchError::ProtectedProcessImmune {
                pid,
                name: "system_anchor".to_string(),
                reason: "Cannot tarpit core system PID or agent self",
            });
        }

        if let Some(existing) = self.active_traps.get(&pid) {
            if existing.load(Ordering::Relaxed) {
                debug!("PID {} is already actively tarpitted.", pid);
                return Ok(());
            }
        }

        #[cfg(target_os = "windows")]
        {
            self.trap_pid_windows(pid, suspend_interval, burst_interval, max_duration)
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.trap_pid_unix(pid, suspend_interval, burst_interval, max_duration)
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            let run_flag = Arc::new(AtomicBool::new(true));
            self.active_traps.insert(pid, run_flag);
            let _ = (suspend_interval, burst_interval, max_duration);
            Ok(())
        }
    }

    #[cfg(target_os = "windows")]
    fn trap_pid_windows(
        &self,
        pid: u32,
        suspend_interval: Duration,
        burst_interval: Duration,
        max_duration: Duration,
    ) -> Result<(), KillSwitchError> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD,
            THREADENTRY32,
        };
        use windows_sys::Win32::System::Threading::{
            OpenThread, ResumeThread, SuspendThread, THREAD_QUERY_INFORMATION,
            THREAD_SUSPEND_RESUME,
        };

        #[derive(Clone, Copy)]
        struct SendHandle(windows_sys::Win32::Foundation::HANDLE);
        unsafe impl Send for SendHandle {}
        unsafe impl Sync for SendHandle {}

        let handles: Vec<SendHandle> = unsafe {
            let mut list = Vec::new();
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot.is_null() {
                let win32_code = windows_sys::Win32::Foundation::GetLastError();
                return Err(KillSwitchError::ThreadSnapshotFailed { pid, win32_code });
            }

            let mut entry: THREADENTRY32 = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;

            if Thread32First(snapshot, &mut entry) != 0 {
                loop {
                    if entry.th32OwnerProcessID == pid {
                        let h = OpenThread(
                            THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                            0,
                            entry.th32ThreadID,
                        );
                        if !h.is_null() {
                            list.push(SendHandle(h));
                        }
                    }
                    if Thread32Next(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
            list
        };

        if handles.is_empty() {
            return Err(KillSwitchError::ThreadSnapshotFailed {
                pid,
                win32_code: 0x00000002, // ERROR_FILE_NOT_FOUND (no threads found)
            });
        }

        let run_flag = Arc::new(AtomicBool::new(true));
        self.active_traps.insert(pid, run_flag.clone());
        let traps = self.active_traps.clone();

        tokio::spawn(async move {
            info!(
                "🚨 [ActiveProcessTarpit] Starting asymmetric containment loop on PID {} ({} threads).",
                pid,
                handles.len()
            );
            let start = tokio::time::Instant::now();
            let mut is_suspended = false;

            while run_flag.load(Ordering::Relaxed) && start.elapsed() < max_duration {
                // Suspend all threads
                for &h in &handles {
                    unsafe {
                        SuspendThread(h.0);
                    }
                }
                is_suspended = true;

                // Chunked sleep to allow quick abort on release
                let chunk = Duration::from_millis(10);
                let mut slept = Duration::ZERO;
                while slept < suspend_interval
                    && run_flag.load(Ordering::Relaxed)
                    && start.elapsed() < max_duration
                {
                    let step = chunk.min(suspend_interval - slept);
                    tokio::time::sleep(step).await;
                    slept += step;
                }

                if !run_flag.load(Ordering::Relaxed) || start.elapsed() >= max_duration {
                    break;
                }

                // Briefly resume for observation burst
                for &h in &handles {
                    unsafe {
                        ResumeThread(h.0);
                    }
                }
                is_suspended = false;

                tokio::time::sleep(burst_interval).await;
            }

            // Cleanup: ensure threads are resumed
            if is_suspended {
                for &h in &handles {
                    unsafe {
                        let mut count = ResumeThread(h.0);
                        while count > 1 && count != u32::MAX {
                            count = ResumeThread(h.0);
                        }
                    }
                }
            }

            // Close handles
            for h in handles {
                unsafe {
                    CloseHandle(h.0);
                }
            }

            // Conditional removal checking Arc pointer equality to prevent ABA race on rapid re-trap
            traps.remove_if(&pid, |_, val| Arc::ptr_eq(val, &run_flag));
            info!(
                "🟢 [ActiveProcessTarpit] Loop terminated and handles cleaned up for PID {}",
                pid
            );
        });

        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn trap_pid_unix(
        &self,
        pid: u32,
        suspend_interval: Duration,
        burst_interval: Duration,
        max_duration: Duration,
    ) -> Result<(), KillSwitchError> {
        let run_flag = Arc::new(AtomicBool::new(true));
        self.active_traps.insert(pid, run_flag.clone());
        let traps = self.active_traps.clone();

        tokio::spawn(async move {
            info!(
                "🚨 [ActiveProcessTarpit] Starting Unix signal duty cycle on PID {}.",
                pid
            );
            let start = tokio::time::Instant::now();
            let mut is_suspended = false;

            while run_flag.load(Ordering::Relaxed) && start.elapsed() < max_duration {
                unsafe {
                    libc::kill(pid as i32, libc::SIGSTOP);
                }
                is_suspended = true;

                let chunk = Duration::from_millis(10);
                let mut slept = Duration::ZERO;
                while slept < suspend_interval
                    && run_flag.load(Ordering::Relaxed)
                    && start.elapsed() < max_duration
                {
                    let step = chunk.min(suspend_interval - slept);
                    tokio::time::sleep(step).await;
                    slept += step;
                }

                if !run_flag.load(Ordering::Relaxed) || start.elapsed() >= max_duration {
                    break;
                }

                unsafe {
                    libc::kill(pid as i32, libc::SIGCONT);
                }
                is_suspended = false;

                tokio::time::sleep(burst_interval).await;
            }

            if is_suspended {
                unsafe {
                    libc::kill(pid as i32, libc::SIGCONT);
                }
            }

            // Conditional removal checking Arc pointer equality to prevent ABA race on rapid re-trap
            traps.remove_if(&pid, |_, val| Arc::ptr_eq(val, &run_flag));
            info!(
                "🟢 [ActiveProcessTarpit] Unix duty cycle ended for PID {}",
                pid
            );
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tarpit_lifecycle_immune() {
        let tarpit = ActiveProcessTarpit::new();
        // Core system PID rejected
        assert!(tarpit.trap_pid_default(0).is_err());
        assert!(tarpit.trap_pid_default(4).is_err());
        assert!(tarpit.trap_pid_default(std::process::id()).is_err());
    }

    #[test]
    fn test_tarpit_release_nonexistent() {
        let tarpit = ActiveProcessTarpit::new();
        assert!(!tarpit.is_trapped(999999));
        tarpit.release_pid(999999);
        assert!(!tarpit.is_trapped(999999));
    }

    #[tokio::test]
    async fn test_tarpit_dashmap_removal_aba_race_prevention() {
        let tarpit = ActiveProcessTarpit::new();
        let test_pid = 49152;

        // Simulate Trap 1
        let flag1 = Arc::new(AtomicBool::new(true));
        tarpit.active_traps.insert(test_pid, flag1.clone());
        assert!(tarpit.is_trapped(test_pid));

        // Release Trap 1 (simulated release_pid)
        flag1.store(false, Ordering::SeqCst);
        tarpit.active_traps.remove(&test_pid);
        assert!(!tarpit.is_trapped(test_pid));

        // Rapid Re-trap (Trap 2 inserted before Task 1 loop terminates)
        let flag2 = Arc::new(AtomicBool::new(true));
        tarpit.active_traps.insert(test_pid, flag2.clone());
        assert!(tarpit.is_trapped(test_pid));

        // Task 1 attempts cleanup using remove_if with Arc::ptr_eq
        let removed = tarpit.active_traps.remove_if(&test_pid, |_, val| Arc::ptr_eq(val, &flag1));
        assert!(removed.is_none(), "Old task must NOT remove newly trapped entry!");

        // Trap 2 must still be intact
        assert!(tarpit.is_trapped(test_pid));
        assert!(Arc::ptr_eq(&tarpit.active_traps.get(&test_pid).unwrap(), &flag2));

        // Task 2 cleans up with its own flag
        let removed2 = tarpit.active_traps.remove_if(&test_pid, |_, val| Arc::ptr_eq(val, &flag2));
        assert!(removed2.is_some(), "Active task must successfully remove its own entry upon termination");
        assert!(!tarpit.is_trapped(test_pid));
    }
}
