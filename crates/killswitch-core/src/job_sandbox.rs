//! Cross-OS Process Tree Sandboxing & Fixed-Point Subtree Containment
//!
//! Enforces whole-subtree isolation rather than single-PID whack-a-mole:
//! - Windows: Strict Win32 Job Objects (`CreateJobObjectW` + `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`),
//!   fail-closed `CREATE_SUSPENDED -> AssignProcessToJobObject -> IsProcessInJob -> ResumeThread`
//!   spawn gating, `QueryInformationJobObject(JobObjectBasicProcessIdList)`, and fixed-point
//!   parent-before-child suspension across all live descendants.
//! - Linux: Unified cgroups v2 (`cgroup.procs` + `cgroup.freeze` `"1"`/`"0"`) when accessible, paired
//!   with `/proc/<pid>/task/*/children` + `sysinfo` fixed-point parent-before-child `SIGSTOP`
//!   until a verification pass detects zero newly spawned unfrozen descendants.
//! - macOS: Darwin `libproc` `proc_listchildpids` + `sysinfo` recursive parent-before-child
//!   fixed-point `SIGSTOP` enforcement across child trees.

use crate::agent_registry::TrackedAgentTreeRegistry;
use crate::freeze::NativeProcessFreezer;
use crate::killchain::{is_critical_system_pid, is_immutable_os_kernel_pid};
use killswitch_types::errors::{KillSwitchError, KillSwitchResult};
use killswitch_types::status::{ProcessFreezer, ProcessIsolationState};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet, VecDeque};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use sysinfo::{Pid, ProcessRefreshKind, System};

#[cfg(target_os = "macos")]
extern "C" {
    fn proc_listchildpids(
        ppid: libc::c_int,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
}

static SANDBOX_SEQ: AtomicU64 = AtomicU64::new(1);

#[cfg(target_os = "windows")]
static ACTIVE_CONTAINMENT_JOBS: OnceLock<Mutex<Vec<WindowsJobSandbox>>> = OnceLock::new();
#[cfg(target_os = "linux")]
static ACTIVE_CONTAINMENT_CGROUPS: OnceLock<Mutex<Vec<LinuxCgroupSandbox>>> = OnceLock::new();

/// Configuration for creating a kernel-enforced process subtree sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobSandboxConfig {
    pub sandbox_id: String,
    pub agent_id: String,
    pub active_process_limit: Option<u32>,
    pub kill_on_close: bool,
}

impl JobSandboxConfig {
    pub fn new(sandbox_id: impl Into<String>, agent_id: impl Into<String>) -> Self {
        Self {
            sandbox_id: sandbox_id.into(),
            agent_id: agent_id.into(),
            active_process_limit: None,
            kill_on_close: true,
        }
    }
}

/// Handle wrapping a child process spawned inside an OS kernel containment sandbox.
pub struct ConfinedChild {
    pub child: Child,
    pub pid: u32,
    pub sandbox_id: String,
    #[cfg(target_os = "windows")]
    job: Option<WindowsJobSandbox>,
    #[cfg(target_os = "linux")]
    cgroup: Option<LinuxCgroupSandbox>,
}

impl ConfinedChild {
    /// Returns the root OS PID of the confined process tree.
    #[inline]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Queries all live member PIDs inside the kernel sandbox or descendant subtree.
    pub fn member_pids(&self) -> KillSwitchResult<Vec<u32>> {
        #[cfg(target_os = "windows")]
        if let Some(ref job) = self.job {
            let mut pids = job.member_pids()?;
            let live = enumerate_live_descendants(self.pid);
            for p in live {
                if !pids.contains(&p) {
                    pids.push(p);
                }
            }
            return Ok(pids);
        }
        #[cfg(target_os = "linux")]
        if let Some(ref cg) = self.cgroup {
            let mut pids = cg.member_pids().unwrap_or_default();
            for p in enumerate_live_descendants(self.pid) {
                if !pids.contains(&p) {
                    pids.push(p);
                }
            }
            return Ok(pids);
        }
        Ok(enumerate_live_descendants(self.pid))
    }

    /// Terminates the entire confined process tree atomically where supported.
    pub fn terminate(&mut self, exit_code: u32) -> KillSwitchResult<()> {
        #[cfg(target_os = "windows")]
        if let Some(ref job) = self.job {
            let res = job.terminate(exit_code);
            let _ = self.child.wait();
            TrackedAgentTreeRegistry::global().unregister_pid(self.pid);
            return res;
        }
        #[cfg(target_os = "linux")]
        if let Some(ref cg) = self.cgroup {
            let _ = cg.terminate();
        }
        let _ = exit_code;
        for pid in enumerate_live_descendants(self.pid).into_iter().rev() {
            if pid != self.pid {
                #[cfg(unix)]
                unsafe {
                    let _ = libc::kill(pid as libc::pid_t, libc::SIGKILL);
                }
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        TrackedAgentTreeRegistry::global().unregister_pid(self.pid);
        Ok(())
    }
}

/// Summary report returned after engaging whole-subtree process containment.
#[derive(Debug, Clone)]
pub struct SubtreeFreezeReport {
    pub root_pid: u32,
    pub kernel_mechanism: &'static str,
    pub job_bound_pids: Vec<u32>,
    pub frozen_records: Vec<ProcessIsolationState>,
    pub frozen_pids: Vec<u32>,
    pub failed_pids: Vec<(u32, String)>,
    pub spared_host_pids: Vec<u32>,
    pub fixed_point_passes: usize,
    pub residual_unfrozen_children: usize,
}

/// Launches `command` confined inside an OS kernel sandbox (Win32 Job Object on Windows via
/// `CREATE_SUSPENDED -> AssignProcessToJobObject -> IsProcessInJob -> ResumeThread`; cgroup v2 or
/// tracked subtree on Linux/macOS) and registers its PID as a `TrackedAgentRoot`.
pub fn spawn_confined_process(
    command: &mut Command,
    label: &str,
) -> KillSwitchResult<ConfinedChild> {
    let seq = SANDBOX_SEQ.fetch_add(1, Ordering::Relaxed);
    let sandbox_id = format!("ks-sandbox-{seq}");

    #[cfg(target_os = "windows")]
    {
        let config = JobSandboxConfig::new(sandbox_id.clone(), label);
        let job = WindowsJobSandbox::create(config)?;
        let child = job.spawn_contained(command)?;
        let pid = child.id();
        Ok(ConfinedChild {
            child,
            pid,
            sandbox_id,
            job: Some(job),
        })
    }

    #[cfg(not(target_os = "windows"))]
    {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            let prepared = crate::landlock::PreparedLinuxSandbox::prepare_seccomp_only(true, false);
            unsafe {
                command.pre_exec(move || prepared.apply_in_pre_exec());
            }
        }
        let child = command.spawn()?;
        let pid = child.id();
        TrackedAgentTreeRegistry::global().register_agent_root_with_sandbox(
            pid,
            label,
            label,
            Some(sandbox_id.clone()),
        );

        #[cfg(target_os = "linux")]
        let cgroup = {
            let cfg = JobSandboxConfig::new(sandbox_id.clone(), label);
            match LinuxCgroupSandbox::create(cfg) {
                Ok(cg) => {
                    let _ = cg.attach_existing_pid(pid);
                    Some(cg)
                }
                Err(_) => None,
            }
        };

        Ok(ConfinedChild {
            child,
            pid,
            sandbox_id,
            #[cfg(target_os = "linux")]
            cgroup,
        })
    }
}

/// Enumerates direct child PIDs of `parent_pid` using OS-native kernel APIs where available,
/// unioned with parent links from the provided `sysinfo::System` snapshot.
fn native_direct_children(parent_pid: u32, sys: &System) -> Vec<u32> {
    let mut children = HashSet::new();

    for (pid_raw, proc_entry) in sys.processes() {
        if let Some(ppid) = proc_entry.parent() {
            if ppid.as_u32() == parent_pid {
                children.insert(pid_raw.as_u32());
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let task_dir = format!("/proc/{parent_pid}/task");
        if let Ok(entries) = std::fs::read_dir(&task_dir) {
            for tid_entry in entries.flatten() {
                let children_path = tid_entry.path().join("children");
                if let Ok(contents) = std::fs::read_to_string(&children_path) {
                    for token in contents.split_whitespace() {
                        if let Ok(cpid) = token.parse::<u32>() {
                            if cpid != parent_pid {
                                children.insert(cpid);
                            }
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        unsafe {
            let needed = proc_listchildpids(parent_pid as libc::c_int, std::ptr::null_mut(), 0);
            if needed > 0 {
                let slot_count = ((needed as usize) / std::mem::size_of::<libc::pid_t>())
                    .max(16)
                    .saturating_mul(2);
                let mut buf = vec![0 as libc::pid_t; slot_count];
                let byte_len = (buf.len() * std::mem::size_of::<libc::pid_t>()) as libc::c_int;
                let written = proc_listchildpids(
                    parent_pid as libc::c_int,
                    buf.as_mut_ptr().cast(),
                    byte_len,
                );
                if written > 0 {
                    let count =
                        ((written as usize) / std::mem::size_of::<libc::pid_t>()).min(buf.len());
                    for &cpid in &buf[..count] {
                        if cpid > 0 && cpid as u32 != parent_pid {
                            children.insert(cpid as u32);
                        }
                    }
                }
            }
        }
    }

    let mut out: Vec<u32> = children.into_iter().collect();
    out.sort_unstable();
    out
}

/// Enumerates `target_pid` and all live descendants in parent-before-child BFS order while
/// strictly excluding `exclude_pids`, immutable OS kernel anchors, and KillSwitch self PIDs.
pub fn enumerate_process_subtree(target_pid: u32, exclude_pids: &HashSet<u32>) -> Vec<u32> {
    if target_pid <= 4 || target_pid == std::process::id() || exclude_pids.contains(&target_pid) {
        return Vec::new();
    }

    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::new());

    let registry = TrackedAgentTreeRegistry::global();
    let reg_children = {
        let mut map: HashMap<u32, Vec<u32>> = HashMap::new();
        for entry in registry.parent_child_edges.iter() {
            map.insert(*entry.key(), entry.value().clone());
        }
        map
    };

    let mut ordered = Vec::new();
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(target_pid);
    visited.insert(target_pid);

    while let Some(pid) = queue.pop_front() {
        if exclude_pids.contains(&pid) || pid == std::process::id() {
            continue;
        }
        let name = sys
            .process(Pid::from_u32(pid))
            .map(|p| p.name())
            .unwrap_or("");
        if is_immutable_os_kernel_pid(pid, name) {
            continue;
        }
        let reg_tainted = registry.is_tracked_pid(pid);
        if !reg_tainted && pid != target_pid && is_critical_system_pid(pid, name) {
            continue;
        }

        ordered.push(pid);

        let mut children = native_direct_children(pid, &sys);
        if let Some(extra) = reg_children.get(&pid) {
            children.extend(extra.iter().copied());
        }
        children.sort_unstable();
        children.dedup();

        for child in children {
            if visited.insert(child) {
                let _ = registry.register_child(child, pid);
                queue.push_back(child);
            }
        }
    }

    ordered
}

/// Enumerates `root_pid` and all live descendants in BFS parent-before-child order,
/// excluding immutable OS kernel anchors and KillSwitch self PIDs.
pub fn enumerate_live_descendants(root_pid: u32) -> Vec<u32> {
    enumerate_process_subtree(root_pid, &HashSet::new())
}

/// Engages kernel-assisted fixed-point parent-before-child subtree containment across
/// all `seed_pids`, binding Win32 Job Objects / Linux cgroups v2 where available and running up
/// to 5 convergence passes until zero newly spawned unfrozen descendants remain.
pub fn freeze_subtree_kernel(
    seed_pids: &[u32],
    immune_pids: &HashSet<u32>,
    freezer: &dyn ProcessFreezer,
) -> SubtreeFreezeReport {
    let root_pid = *seed_pids.first().unwrap_or(&0);
    let mut kernel_mechanism: &'static str = {
        #[cfg(target_os = "windows")]
        {
            "win32_ntsuspend_fixed_point"
        }
        #[cfg(target_os = "linux")]
        {
            "linux_proc_sigstop_fixed_point"
        }
        #[cfg(target_os = "macos")]
        {
            "macos_libproc_sigstop_fixed_point"
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            "posix_sigstop_fixed_point"
        }
    };

    let mut job_bound_pids = Vec::new();

    #[cfg(target_os = "windows")]
    let containment_job: Option<WindowsJobSandbox> = if !seed_pids.is_empty() {
        let seq = SANDBOX_SEQ.fetch_add(1, Ordering::Relaxed);
        // Containment attachments use kill_on_close=false so operator disarm releases
        // the job wrapper cleanly before resuming processes.
        let mut cfg =
            JobSandboxConfig::new(format!("ks-contain-{seq}"), format!("root-{root_pid}"));
        cfg.kill_on_close = false;
        WindowsJobSandbox::create(cfg).ok()
    } else {
        None
    };

    #[cfg(target_os = "linux")]
    let containment_cgroup: Option<LinuxCgroupSandbox> = if !seed_pids.is_empty() {
        let seq = SANDBOX_SEQ.fetch_add(1, Ordering::Relaxed);
        let cfg = JobSandboxConfig::new(format!("ks-contain-{seq}"), format!("root-{root_pid}"));
        LinuxCgroupSandbox::create(cfg).ok()
    } else {
        None
    };

    let mut frozen_set = HashSet::new();
    let mut frozen_pids = Vec::new();
    let mut frozen_records = Vec::new();
    let mut failed_pids = Vec::new();
    let mut failed_seen = HashSet::new();
    let mut spared_set = HashSet::new();
    let mut passes = 0usize;

    const MAX_FIXED_POINT_PASSES: usize = 5;
    for _ in 0..MAX_FIXED_POINT_PASSES {
        passes += 1;

        let mut expanded = Vec::new();
        let mut exp_seen = HashSet::new();
        for &seed in seed_pids {
            for pid in enumerate_process_subtree(seed, immune_pids) {
                if exp_seen.insert(pid) {
                    expanded.push(pid);
                }
            }
        }

        #[cfg(target_os = "windows")]
        if let Some(ref job) = containment_job {
            for &pid in &expanded {
                if !job_bound_pids.contains(&pid)
                    && matches!(job.attach_existing_pid(pid), Ok(true))
                {
                    job_bound_pids.push(pid);
                }
            }
            if let Ok(job_members) = job.member_pids() {
                for mpid in job_members {
                    if !immune_pids.contains(&mpid)
                        && mpid > 4
                        && mpid != std::process::id()
                        && exp_seen.insert(mpid)
                    {
                        expanded.push(mpid);
                    }
                    if !job_bound_pids.contains(&mpid) {
                        job_bound_pids.push(mpid);
                    }
                }
            }
            if !job_bound_pids.is_empty() {
                kernel_mechanism = "win32_job_object+ntsuspend_fixed_point";
            }
        }

        #[cfg(target_os = "linux")]
        if let Some(ref cg) = containment_cgroup {
            for &pid in &expanded {
                if !job_bound_pids.contains(&pid) && cg.attach_existing_pid(pid).is_ok() {
                    job_bound_pids.push(pid);
                }
            }
            if !job_bound_pids.is_empty() && cg.freeze().is_ok() {
                kernel_mechanism = "linux_cgroup_v2+sigstop_fixed_point";
                if let Ok(cg_members) = cg.member_pids() {
                    for mpid in cg_members {
                        if !immune_pids.contains(&mpid)
                            && mpid > 4
                            && mpid != std::process::id()
                            && exp_seen.insert(mpid)
                        {
                            expanded.push(mpid);
                        }
                    }
                }
            }
        }

        let mut newly_frozen_in_pass = 0usize;
        for pid in expanded {
            if immune_pids.contains(&pid) || pid <= 4 || pid == std::process::id() {
                spared_set.insert(pid);
                continue;
            }
            if frozen_set.contains(&pid) {
                continue;
            }
            match freezer.freeze_process(pid) {
                Ok(state) => {
                    frozen_set.insert(pid);
                    frozen_pids.push(pid);
                    frozen_records.push(state);
                    newly_frozen_in_pass += 1;
                }
                Err(KillSwitchError::ProtectedProcessImmune { .. })
                | Err(KillSwitchError::ParentLineageImmune { .. }) => {
                    spared_set.insert(pid);
                }
                Err(err) => {
                    if failed_seen.insert(pid) {
                        failed_pids.push((pid, err.to_string()));
                    }
                }
            }
        }

        if newly_frozen_in_pass == 0 {
            break;
        }
    }

    let mut residual = 0usize;
    for &seed in seed_pids {
        for pid in enumerate_process_subtree(seed, immune_pids) {
            if !frozen_set.contains(&pid) && !immune_pids.contains(&pid) {
                residual += 1;
            }
        }
    }

    #[cfg(target_os = "windows")]
    if let Some(job) = containment_job {
        if !job_bound_pids.is_empty() {
            ACTIVE_CONTAINMENT_JOBS
                .get_or_init(|| Mutex::new(Vec::new()))
                .lock()
                .push(job);
        }
    }

    #[cfg(target_os = "linux")]
    if let Some(cg) = containment_cgroup {
        if !job_bound_pids.is_empty() {
            ACTIVE_CONTAINMENT_CGROUPS
                .get_or_init(|| Mutex::new(Vec::new()))
                .lock()
                .push(cg);
        }
    }

    SubtreeFreezeReport {
        root_pid,
        kernel_mechanism,
        job_bound_pids,
        frozen_records,
        frozen_pids,
        failed_pids,
        spared_host_pids: spared_set.into_iter().collect(),
        fixed_point_passes: passes,
        residual_unfrozen_children: residual,
    }
}

/// Releases managed containment job/cgroup wrappers when disarming host isolation.
pub fn release_all_sandbox_jobs() {
    #[cfg(target_os = "windows")]
    if let Some(lock) = ACTIVE_CONTAINMENT_JOBS.get() {
        lock.lock().clear();
    }
    #[cfg(target_os = "linux")]
    if let Some(lock) = ACTIVE_CONTAINMENT_CGROUPS.get() {
        let mut guard = lock.lock();
        for cg in guard.drain(..) {
            let _ = cg.thaw();
        }
    }
}

/// Freezes `root_pid` and its entire descendant subtree using fixed-point containment.
pub fn freeze_process_subtree(
    root_pid: u32,
    freezer: &NativeProcessFreezer,
) -> KillSwitchResult<SubtreeFreezeReport> {
    if root_pid <= 4 || root_pid == std::process::id() {
        return Err(KillSwitchError::ProtectedProcessImmune {
            pid: root_pid,
            name: String::new(),
            reason: "Refusing subtree freeze on kernel/self PID",
        });
    }

    let immune_pids = freezer.get_immune_pids();
    if immune_pids.contains(&root_pid) {
        return Err(KillSwitchError::ParentLineageImmune {
            pid: root_pid,
            ancestor_pid: root_pid,
            ancestor_name: String::new(),
            depth: 0,
        });
    }

    let registry = TrackedAgentTreeRegistry::global();
    registry.mark_confirmed_threat(root_pid, "Subtree quarantine engaged");

    let report = freeze_subtree_kernel(&[root_pid], &immune_pids, freezer);
    if report.frozen_pids.is_empty() {
        if let Some((_, err_msg)) = report.failed_pids.first() {
            return Err(KillSwitchError::NativeOsError(format!(
                "Failed to freeze subtree rooted at PID {root_pid}: {err_msg}"
            )));
        }
    }
    Ok(report)
}

/// Resumes `root_pid` and any live descendants, thawing active sandboxes first.
pub fn resume_process_subtree(
    root_pid: u32,
    freezer: &NativeProcessFreezer,
) -> KillSwitchResult<Vec<u32>> {
    release_all_sandbox_jobs();

    let mut targets = enumerate_live_descendants(root_pid);
    targets.reverse();
    let mut resumed = Vec::new();
    for pid in targets {
        if freezer.resume_process(pid).is_ok() {
            resumed.push(pid);
        }
    }
    TrackedAgentTreeRegistry::global()
        .confirmed_threat_pids
        .remove(&root_pid);
    Ok(resumed)
}

// =============================================================================
// Windows Win32 Job Object Sandbox
// =============================================================================

#[cfg(target_os = "windows")]
pub struct WindowsJobSandbox {
    config: JobSandboxConfig,
    handle_raw: usize,
}

#[cfg(target_os = "windows")]
impl WindowsJobSandbox {
    /// Creates a hardened Windows Job Object with configurable `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
    /// and optional `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`.
    pub fn create(config: JobSandboxConfig) -> KillSwitchResult<Self> {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::JobObjects::{
            CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };

        let h_job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|e| KillSwitchError::NativeOsError(format!("CreateJobObjectW failed: {e}")))?;

        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        if config.kill_on_close {
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        }
        if let Some(max_procs) = config.active_process_limit {
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            limits.BasicLimitInformation.ActiveProcessLimit = max_procs.max(1);
        }

        let set_res = unsafe {
            SetInformationJobObject(
                h_job,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(limits).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if let Err(e) = set_res {
            unsafe {
                let _ = CloseHandle(h_job);
            }
            return Err(KillSwitchError::NativeOsError(format!(
                "SetInformationJobObject failed: {e}"
            )));
        }

        Ok(Self {
            config,
            handle_raw: h_job.0 as usize,
        })
    }

    #[inline]
    fn handle(&self) -> windows::Win32::Foundation::HANDLE {
        windows::Win32::Foundation::HANDLE(self.handle_raw as *mut core::ffi::c_void)
    }

    /// Launches an AI agent command fail-closed inside this Job Object:
    /// 1. Spawns child with `CREATE_SUSPENDED (0x0000_0004)`;
    /// 2. Calls `AssignProcessToJobObject`;
    /// 3. Asserts `IsProcessInJob == TRUE` BEFORE calling `ResumeThread`;
    /// 4. Immediately terminates suspended child on any confinement failure.
    pub fn spawn_contained(&self, command: &mut Command) -> KillSwitchResult<Child> {
        use std::os::windows::io::AsRawHandle;
        use std::os::windows::process::CommandExt;
        use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use windows::Win32::System::JobObjects::{AssignProcessToJobObject, IsProcessInJob};
        use windows::Win32::System::Threading::{
            OpenThread, ResumeThread, CREATE_SUSPENDED, THREAD_SUSPEND_RESUME,
        };

        command.creation_flags(CREATE_SUSPENDED.0);
        let mut child = command.spawn()?;
        let child_pid = child.id();
        let proc_handle = HANDLE(child.as_raw_handle());

        if let Err(e) = unsafe { AssignProcessToJobObject(self.handle(), proc_handle) } {
            let _ = child.kill();
            let _ = child.wait();
            return Err(KillSwitchError::NativeOsError(format!(
                "AssignProcessToJobObject failed for PID {child_pid}: {e}"
            )));
        }

        let mut in_job = BOOL(0);
        if let Err(e) = unsafe { IsProcessInJob(proc_handle, self.handle(), &mut in_job) } {
            let _ = child.kill();
            let _ = child.wait();
            return Err(KillSwitchError::NativeOsError(format!(
                "IsProcessInJob failed for PID {child_pid}: {e}"
            )));
        }
        if !in_job.as_bool() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(KillSwitchError::NativeOsError(format!(
                "Fail-closed: PID {child_pid} failed IsProcessInJob check before ResumeThread"
            )));
        }

        TrackedAgentTreeRegistry::global().register_agent_root_with_sandbox(
            child_pid,
            self.config.agent_id.clone(),
            self.config.agent_id.clone(),
            Some(self.config.sandbox_id.clone()),
        );

        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }.map_err(|e| {
            let _ = child.kill();
            let _ = child.wait();
            TrackedAgentTreeRegistry::global().unregister_pid(child_pid);
            KillSwitchError::NativeOsError(format!(
                "CreateToolhelp32Snapshot failed before ResumeThread for PID {child_pid}: {e}"
            ))
        })?;

        let mut te = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let mut resumed_any = false;
        let mut iter_ok = unsafe { Thread32First(snap, &mut te) }.is_ok();
        while iter_ok {
            if te.th32OwnerProcessID == child_pid {
                if let Ok(h_thread) =
                    unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, te.th32ThreadID) }
                {
                    let prev_count = unsafe { ResumeThread(h_thread) };
                    unsafe {
                        let _ = CloseHandle(h_thread);
                    }
                    if prev_count != u32::MAX {
                        resumed_any = true;
                    }
                }
            }
            te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            iter_ok = unsafe { Thread32Next(snap, &mut te) }.is_ok();
        }
        unsafe {
            let _ = CloseHandle(snap);
        }

        if !resumed_any {
            let _ = child.kill();
            let _ = child.wait();
            TrackedAgentTreeRegistry::global().unregister_pid(child_pid);
            return Err(KillSwitchError::NativeOsError(format!(
                "Failed to locate and resume initial thread for PID {child_pid}"
            )));
        }

        Ok(child)
    }

    /// Attaches an existing running process (and its future children) to this Job Object,
    /// verifying `IsProcessInJob == TRUE`.
    pub fn attach_existing_pid(&self, pid: u32) -> KillSwitchResult<bool> {
        use windows::Win32::Foundation::{CloseHandle, BOOL};
        use windows::Win32::System::JobObjects::{AssignProcessToJobObject, IsProcessInJob};
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA, PROCESS_TERMINATE,
        };

        let h_proc = unsafe {
            OpenProcess(
                PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid,
            )
        }
        .map_err(|e| {
            KillSwitchError::NativeOsError(format!(
                "OpenProcess failed while attaching PID {pid} to job: {e}"
            ))
        })?;

        let assign_res = unsafe { AssignProcessToJobObject(self.handle(), h_proc) };
        if let Err(e) = assign_res {
            unsafe {
                let _ = CloseHandle(h_proc);
            }
            return Err(KillSwitchError::NativeOsError(format!(
                "AssignProcessToJobObject failed for PID {pid}: {e}"
            )));
        }

        let mut in_job = BOOL(0);
        let check_res = unsafe { IsProcessInJob(h_proc, self.handle(), &mut in_job) };
        unsafe {
            let _ = CloseHandle(h_proc);
        }
        check_res.map_err(|e| {
            KillSwitchError::NativeOsError(format!("IsProcessInJob failed for PID {pid}: {e}"))
        })?;
        Ok(in_job.as_bool())
    }

    /// Queries kernel `JobObjectBasicProcessIdList` for all live PIDs currently confined inside
    /// this Job Object (including deeply nested child shells).
    pub fn member_pids(&self) -> KillSwitchResult<Vec<u32>> {
        use windows::Win32::Foundation::ERROR_MORE_DATA;
        use windows::Win32::System::JobObjects::{
            JobObjectBasicProcessIdList, QueryInformationJobObject, JOBOBJECT_BASIC_PROCESS_ID_LIST,
        };

        let mut slots = 256usize;
        loop {
            let mut buf = vec![0usize; slots];
            let byte_len = (buf.len() * std::mem::size_of::<usize>()) as u32;
            let mut returned = 0u32;
            let res = unsafe {
                QueryInformationJobObject(
                    self.handle(),
                    JobObjectBasicProcessIdList,
                    buf.as_mut_ptr().cast(),
                    byte_len,
                    Some(&mut returned),
                )
            };

            match res {
                Ok(()) => {
                    let header =
                        unsafe { &*(buf.as_ptr() as *const JOBOBJECT_BASIC_PROCESS_ID_LIST) };
                    let count = header.NumberOfProcessIdsInList as usize;
                    let list_offset =
                        std::mem::offset_of!(JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList);
                    let list_ptr =
                        unsafe { buf.as_ptr().cast::<u8>().add(list_offset) } as *const usize;
                    let max_possible = (buf.len() * std::mem::size_of::<usize>() - list_offset)
                        / std::mem::size_of::<usize>();
                    let safe_count = count.min(max_possible);
                    let mut pids = Vec::with_capacity(safe_count);
                    for idx in 0..safe_count {
                        let raw_pid = unsafe { *list_ptr.add(idx) };
                        if let Ok(pid) = u32::try_from(raw_pid) {
                            if pid > 0 {
                                pids.push(pid);
                            }
                        }
                    }
                    return Ok(pids);
                }
                Err(e) if e.code() == ERROR_MORE_DATA.to_hresult() && slots < 65_536 => {
                    slots *= 2;
                }
                Err(e) => {
                    return Err(KillSwitchError::NativeOsError(format!(
                        "QueryInformationJobObject failed: {e}"
                    )));
                }
            }
        }
    }

    /// Freezes every member process currently inside the Job Object via fixed-point
    /// `NtSuspendProcess` passes.
    pub fn freeze_members(
        &self,
        freezer: &NativeProcessFreezer,
    ) -> KillSwitchResult<SubtreeFreezeReport> {
        let immune = freezer.get_immune_pids();
        let mut frozen_set = HashSet::new();
        let mut frozen_pids = Vec::new();
        let mut frozen_records = Vec::new();
        let mut failed_pids = Vec::new();
        let mut passes = 0usize;
        let mut root_pid = 0u32;
        let mut job_bound = Vec::new();

        for _ in 0..5 {
            passes += 1;
            let mut members = self.member_pids()?;
            members.sort_unstable();
            if root_pid == 0 {
                root_pid = *members.first().unwrap_or(&0);
            }
            for &m in &members {
                if !job_bound.contains(&m) {
                    job_bound.push(m);
                }
            }
            let mut newly_frozen = 0usize;
            for pid in members {
                if immune.contains(&pid) || pid <= 4 || pid == std::process::id() {
                    continue;
                }
                if frozen_set.contains(&pid) {
                    continue;
                }
                match freezer.freeze_single_pid_raw(pid) {
                    Ok(state) => {
                        frozen_set.insert(pid);
                        frozen_pids.push(pid);
                        frozen_records.push(state);
                        newly_frozen += 1;
                    }
                    Err(e) => {
                        failed_pids.push((pid, e.to_string()));
                    }
                }
            }
            if newly_frozen == 0 {
                break;
            }
        }

        let residual_unfrozen_children = self
            .member_pids()
            .unwrap_or_default()
            .into_iter()
            .filter(|pid| !frozen_set.contains(pid) && !immune.contains(pid))
            .count();

        Ok(SubtreeFreezeReport {
            root_pid,
            kernel_mechanism: "win32_job_object+ntsuspend_fixed_point",
            job_bound_pids: job_bound,
            frozen_records,
            frozen_pids,
            failed_pids,
            spared_host_pids: Vec::new(),
            fixed_point_passes: passes,
            residual_unfrozen_children,
        })
    }

    /// Kernel-atomic termination of the entire process tree in the Job Object.
    pub fn terminate(&self, exit_code: u32) -> KillSwitchResult<()> {
        use windows::Win32::System::JobObjects::TerminateJobObject;
        unsafe { TerminateJobObject(self.handle(), exit_code) }
            .map_err(|e| KillSwitchError::NativeOsError(format!("TerminateJobObject failed: {e}")))
    }
}

#[cfg(target_os = "windows")]
impl Drop for WindowsJobSandbox {
    fn drop(&mut self) {
        if self.handle_raw != 0 {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(self.handle());
            }
            self.handle_raw = 0;
        }
    }
}

// =============================================================================
// Cross-OS Capabilityless Sandbox Launch (`AppContainer` + Job / Landlock / Seatbelt)
// =============================================================================

/// Configuration for launching an AI agent command inside a strict OS sandbox
/// (Windows AppContainer + Job Object; Linux cgroup v2 + Landlock + seccomp; macOS Seatbelt).
#[derive(Debug, Clone)]
pub struct SandboxedAgentConfig {
    pub agent_id: String,
    pub program: String,
    pub args: Vec<String>,
    pub current_dir: Option<std::path::PathBuf>,
    pub readable_paths: Vec<std::path::PathBuf>,
    pub writable_paths: Vec<std::path::PathBuf>,
    pub active_process_limit: Option<u32>,
    pub allow_network: bool,
    pub kill_on_close: bool,
}

impl SandboxedAgentConfig {
    pub fn new(agent_id: impl Into<String>, program: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            program: program.into(),
            args: Vec::new(),
            current_dir: None,
            readable_paths: Vec::new(),
            writable_paths: Vec::new(),
            active_process_limit: None,
            allow_network: false,
            kill_on_close: true,
        }
    }
}

/// Live confined AI agent root handle returned by `spawn_sandboxed_agent_process`.
pub struct SandboxedAgentProcess {
    pub pid: u32,
    pub sandbox_id: String,
    pub isolation_mode: &'static str,
    pub is_appcontainer: bool,
    #[cfg(target_os = "windows")]
    process_handle_raw: usize,
    #[cfg(target_os = "windows")]
    appcontainer_profile: Option<String>,
    #[cfg(target_os = "windows")]
    job: Option<WindowsJobSandbox>,
    #[cfg(not(target_os = "windows"))]
    child: Option<Child>,
    #[cfg(target_os = "linux")]
    cgroup: Option<LinuxCgroupSandbox>,
}

impl SandboxedAgentProcess {
    #[inline]
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn member_pids(&self) -> KillSwitchResult<Vec<u32>> {
        #[cfg(target_os = "windows")]
        if let Some(ref job) = self.job {
            let mut pids = job.member_pids()?;
            for p in enumerate_live_descendants(self.pid) {
                if !pids.contains(&p) {
                    pids.push(p);
                }
            }
            return Ok(pids);
        }
        #[cfg(target_os = "linux")]
        if let Some(ref cg) = self.cgroup {
            let mut pids = cg.member_pids().unwrap_or_default();
            for p in enumerate_live_descendants(self.pid) {
                if !pids.contains(&p) {
                    pids.push(p);
                }
            }
            return Ok(pids);
        }
        Ok(enumerate_live_descendants(self.pid))
    }

    /// Terminates the confined agent process tree atomically and reclaims sandbox profiles.
    pub fn terminate(&mut self, exit_code: u32) -> KillSwitchResult<()> {
        #[cfg(target_os = "windows")]
        {
            use windows::core::PCWSTR;
            use windows::Win32::Foundation::{CloseHandle, HANDLE};
            use windows::Win32::Security::Isolation::DeleteAppContainerProfile;
            use windows::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};

            let res = if let Some(ref job) = self.job {
                job.terminate(exit_code)
            } else {
                Ok(())
            };
            if self.process_handle_raw != 0 {
                let h_proc = HANDLE(self.process_handle_raw as *mut core::ffi::c_void);
                unsafe {
                    let _ = TerminateProcess(h_proc, exit_code);
                    let _ = WaitForSingleObject(h_proc, 2000);
                    let _ = CloseHandle(h_proc);
                }
                self.process_handle_raw = 0;
            }
            TrackedAgentTreeRegistry::global().unregister_pid(self.pid);
            if let Some(profile) = self.appcontainer_profile.take() {
                let w_name: Vec<u16> = profile.encode_utf16().chain(std::iter::once(0)).collect();
                unsafe {
                    let _ = DeleteAppContainerProfile(PCWSTR(w_name.as_ptr()));
                }
            }
            res
        }
        #[cfg(not(target_os = "windows"))]
        {
            #[cfg(target_os = "linux")]
            if let Some(ref cg) = self.cgroup {
                let _ = cg.terminate();
            }
            let _ = exit_code;
            for pid in enumerate_live_descendants(self.pid).into_iter().rev() {
                if pid != self.pid {
                    #[cfg(unix)]
                    unsafe {
                        let _ = libc::kill(pid as libc::pid_t, libc::SIGKILL);
                    }
                }
            }
            if let Some(ref mut child) = self.child {
                let _ = child.kill();
                let _ = child.wait();
            }
            TrackedAgentTreeRegistry::global().unregister_pid(self.pid);
            Ok(())
        }
    }

    /// Waits for the sandboxed root process to exit and returns its OS exit code.
    pub fn wait_exit_code(&mut self) -> KillSwitchResult<i32> {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::Foundation::{CloseHandle, HANDLE};
            use windows::Win32::System::Threading::{
                GetExitCodeProcess, WaitForSingleObject, INFINITE,
            };
            if self.process_handle_raw == 0 {
                return Err(KillSwitchError::NativeOsError(
                    "Sandboxed Windows process handle already closed".to_string(),
                ));
            }
            let h_proc = HANDLE(self.process_handle_raw as *mut core::ffi::c_void);
            unsafe {
                let _ = WaitForSingleObject(h_proc, INFINITE);
                let mut code: u32 = 1;
                let _ = GetExitCodeProcess(h_proc, &mut code);
                let _ = CloseHandle(h_proc);
                self.process_handle_raw = 0;
                TrackedAgentTreeRegistry::global().unregister_pid(self.pid);
                Ok(code as i32)
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let status = if let Some(ref mut child) = self.child {
                child.wait()?
            } else {
                return Err(KillSwitchError::NativeOsError(
                    "Sandboxed child handle already consumed".to_string(),
                ));
            };
            TrackedAgentTreeRegistry::global().unregister_pid(self.pid);
            Ok(status.code().unwrap_or(1))
        }
    }
}

impl Drop for SandboxedAgentProcess {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            use windows::core::PCWSTR;
            use windows::Win32::Foundation::{CloseHandle, HANDLE};
            use windows::Win32::Security::Isolation::DeleteAppContainerProfile;
            use windows::Win32::System::Threading::WaitForSingleObject;

            let kill_on_close = self
                .job
                .as_ref()
                .map(|j| j.config.kill_on_close)
                .unwrap_or(false);
            drop(self.job.take());
            if self.process_handle_raw != 0 {
                let h_proc = HANDLE(self.process_handle_raw as *mut core::ffi::c_void);
                unsafe {
                    if kill_on_close {
                        let _ = WaitForSingleObject(h_proc, 1000);
                    }
                    let _ = CloseHandle(h_proc);
                }
                self.process_handle_raw = 0;
            }
            if kill_on_close {
                TrackedAgentTreeRegistry::global().unregister_pid(self.pid);
                if let Some(profile) = self.appcontainer_profile.take() {
                    let w_name: Vec<u16> =
                        profile.encode_utf16().chain(std::iter::once(0)).collect();
                    unsafe {
                        let _ = DeleteAppContainerProfile(PCWSTR(w_name.as_ptr()));
                    }
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            TrackedAgentTreeRegistry::global().unregister_pid(self.pid);
        }
    }
}

/// Formats a Windows `CreateProcessW` command line from `program` and `args` using
/// Win32 `CommandLineToArgvW` backslash escaping rules.
pub fn format_windows_command_line(program: &str, args: &[String]) -> String {
    fn push_quoted_arg(out: &mut String, arg: &str) {
        if !out.is_empty() {
            out.push(' ');
        }
        let needs_quotes = arg.is_empty()
            || arg
                .chars()
                .any(|c| c == ' ' || c == '\t' || c == '"' || c == '\n' || c == '\r');
        if !needs_quotes {
            out.push_str(arg);
            return;
        }
        out.push('"');
        let mut backslashes = 0usize;
        for ch in arg.chars() {
            match ch {
                '\\' => backslashes += 1,
                '"' => {
                    for _ in 0..(backslashes * 2 + 1) {
                        out.push('\\');
                    }
                    out.push('"');
                    backslashes = 0;
                }
                _ => {
                    for _ in 0..backslashes {
                        out.push('\\');
                    }
                    backslashes = 0;
                    out.push(ch);
                }
            }
        }
        for _ in 0..(backslashes * 2) {
            out.push('\\');
        }
        out.push('"');
    }

    let mut cmdline = String::new();
    push_quoted_arg(&mut cmdline, program);
    for a in args {
        push_quoted_arg(&mut cmdline, a);
    }
    cmdline
}

/// Capabilityless Windows AppContainer + Job Object sandbox.
///
/// Launches children with:
/// - Zero AppContainer capabilities (`Capabilities = NULL, CapabilityCount = 0`) blocking network/UNC/documents
/// - `EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW`
/// - Mandatory `AssignProcessToJobObject` + `IsProcessInJob == TRUE` + `TokenIsAppContainer != 0`
///   verification strictly BEFORE `ResumeThread`
/// - Automatic suspended termination, `FreeSid`, `DeleteProcThreadAttributeList`, and
///   `DeleteAppContainerProfile` rollback on any failure.
#[cfg(target_os = "windows")]
pub struct WindowsAppContainerSandbox;

#[cfg(target_os = "windows")]
impl WindowsAppContainerSandbox {
    fn sanitize_profile_name(sandbox_id: &str) -> String {
        let cleaned: String = sandbox_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
            .collect();
        let raw = format!("ks.ac.{cleaned}");
        if raw.len() > 64 {
            raw[..64].to_string()
        } else {
            raw
        }
    }

    pub fn spawn(
        config: &SandboxedAgentConfig,
        sandbox_id: &str,
    ) -> KillSwitchResult<SandboxedAgentProcess> {
        use windows::core::{PCWSTR, PWSTR};
        use windows::Win32::Foundation::{CloseHandle, BOOL, HANDLE};
        use windows::Win32::Security::Isolation::{
            CreateAppContainerProfile, DeleteAppContainerProfile,
            DeriveAppContainerSidFromAppContainerName,
        };
        use windows::Win32::Security::{
            FreeSid, GetTokenInformation, TokenIsAppContainer, PSID, SECURITY_CAPABILITIES,
            TOKEN_QUERY,
        };
        use windows::Win32::System::JobObjects::{AssignProcessToJobObject, IsProcessInJob};
        use windows::Win32::System::Threading::{
            CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
            OpenProcessToken, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
            CREATE_NO_WINDOW, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
            LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW,
        };

        if config.allow_network {
            tracing::warn!(
                agent_id = %config.agent_id,
                "AppContainer sandbox ignores allow_network=true and enforces zero-capability isolation"
            );
        }

        let profile_name = Self::sanitize_profile_name(sandbox_id);
        let w_profile: Vec<u16> = profile_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let w_display: Vec<u16> = format!("KillSwitch Sandbox ({})", config.agent_id)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let w_desc: Vec<u16> = "KillSwitch Zero-Capability Agent AppContainer\0"
            .encode_utf16()
            .collect();

        struct ProfileRollbackGuard {
            w_profile: Vec<u16>,
            active: bool,
        }
        impl Drop for ProfileRollbackGuard {
            fn drop(&mut self) {
                if self.active {
                    unsafe {
                        let _ = DeleteAppContainerProfile(PCWSTR(self.w_profile.as_ptr()));
                    }
                }
            }
        }

        struct SidGuard(PSID);
        impl Drop for SidGuard {
            fn drop(&mut self) {
                if !self.0 .0.is_null() {
                    unsafe {
                        let _ = FreeSid(self.0);
                    }
                    self.0 = PSID(std::ptr::null_mut());
                }
            }
        }

        struct AttrListGuard {
            lp_attr: LPPROC_THREAD_ATTRIBUTE_LIST,
            _backing: Vec<usize>,
        }
        impl Drop for AttrListGuard {
            fn drop(&mut self) {
                if !self.lp_attr.is_invalid() {
                    unsafe { DeleteProcThreadAttributeList(self.lp_attr) };
                    self.lp_attr = LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut());
                }
            }
        }

        // 1. Allocate AppContainer profile & SID (fail-closed, zero uncontained fallback).
        const HRESULT_ALREADY_EXISTS: i32 = 0x8007_00B7u32 as i32;
        let psid = match unsafe {
            CreateAppContainerProfile(
                PCWSTR(w_profile.as_ptr()),
                PCWSTR(w_display.as_ptr()),
                PCWSTR(w_desc.as_ptr()),
                None, // Zero capabilities -> capabilityless sandbox
            )
        } {
            Ok(sid) => sid,
            Err(err) if err.code().0 == HRESULT_ALREADY_EXISTS => unsafe {
                DeriveAppContainerSidFromAppContainerName(PCWSTR(w_profile.as_ptr())).map_err(
                    |e| {
                        KillSwitchError::NativeOsError(format!(
                        "DeriveAppContainerSidFromAppContainerName failed for '{profile_name}': {e}"
                    ))
                    },
                )?
            },
            Err(err) => {
                return Err(KillSwitchError::NativeOsError(format!(
                    "Fail-closed: CreateAppContainerProfile failed for '{profile_name}': {err}"
                )));
            }
        };

        let mut profile_rollback = ProfileRollbackGuard {
            w_profile,
            active: true,
        };
        let sid_guard = SidGuard(psid);
        if sid_guard.0 .0.is_null() {
            return Err(KillSwitchError::NativeOsError(
                "Fail-closed: CreateAppContainerProfile returned null PSID".to_string(),
            ));
        }

        // 2. Create hardened Win32 Job Object BEFORE process launch.
        let mut job_cfg = JobSandboxConfig::new(sandbox_id.to_string(), config.agent_id.clone());
        job_cfg.active_process_limit = config.active_process_limit;
        job_cfg.kill_on_close = config.kill_on_close;
        let job = WindowsJobSandbox::create(job_cfg)?;

        // 3. Allocate & populate PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES.
        let mut attr_size: usize = 0;
        let _ = unsafe {
            InitializeProcThreadAttributeList(
                LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
                1,
                0,
                &mut attr_size,
            )
        };
        if attr_size == 0 {
            return Err(KillSwitchError::NativeOsError(
                "InitializeProcThreadAttributeList returned zero attribute size".to_string(),
            ));
        }
        let words = attr_size.div_ceil(std::mem::size_of::<usize>());
        let mut backing = vec![0usize; words];
        let lp_attr = LPPROC_THREAD_ATTRIBUTE_LIST(backing.as_mut_ptr().cast());
        unsafe { InitializeProcThreadAttributeList(lp_attr, 1, 0, &mut attr_size) }.map_err(
            |e| {
                KillSwitchError::NativeOsError(format!(
                    "InitializeProcThreadAttributeList failed: {e}"
                ))
            },
        )?;
        let attr_guard = AttrListGuard {
            lp_attr,
            _backing: backing,
        };

        let sec_caps = SECURITY_CAPABILITIES {
            AppContainerSid: sid_guard.0,
            Capabilities: std::ptr::null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };
        unsafe {
            UpdateProcThreadAttribute(
                attr_guard.lp_attr,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                Some((&sec_caps as *const SECURITY_CAPABILITIES).cast()),
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                None,
                None,
            )
        }
        .map_err(|e| {
            KillSwitchError::NativeOsError(format!(
                "UpdateProcThreadAttribute(SECURITY_CAPABILITIES) failed: {e}"
            ))
        })?;

        let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.lpAttributeList = attr_guard.lp_attr;

        let cmdline = format_windows_command_line(&config.program, &config.args);
        let mut w_cmdline: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
        let w_cwd: Option<Vec<u16>> = config.current_dir.as_ref().map(|p| {
            p.as_os_str()
                .to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect()
        });
        let cwd_pcwstr = w_cwd
            .as_ref()
            .map(|v| PCWSTR(v.as_ptr()))
            .unwrap_or_else(PCWSTR::null);

        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let spawn_res = unsafe {
            CreateProcessW(
                PCWSTR::null(),
                PWSTR(w_cmdline.as_mut_ptr()),
                None,
                None,
                BOOL(0),
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                None,
                cwd_pcwstr,
                &si.StartupInfo,
                &mut pi,
            )
        };
        // Free Win32 heap allocations (SID + attribute list) immediately once applied.
        drop(attr_guard);
        drop(sid_guard);

        spawn_res.map_err(|e| {
            KillSwitchError::NativeOsError(format!(
                "Fail-closed: CreateProcessW in AppContainer failed for '{}': {e}",
                config.program
            ))
        })?;

        struct SuspendedProcCleanup {
            h_proc: HANDLE,
            h_thread: HANDLE,
            terminate_on_drop: bool,
        }
        impl Drop for SuspendedProcCleanup {
            fn drop(&mut self) {
                if self.terminate_on_drop && !self.h_proc.is_invalid() {
                    unsafe {
                        let _ = TerminateProcess(self.h_proc, 1);
                    }
                }
                if !self.h_thread.is_invalid() {
                    unsafe {
                        let _ = CloseHandle(self.h_thread);
                    }
                    self.h_thread = HANDLE(std::ptr::null_mut());
                }
                if self.terminate_on_drop && !self.h_proc.is_invalid() {
                    unsafe {
                        let _ = CloseHandle(self.h_proc);
                    }
                    self.h_proc = HANDLE(std::ptr::null_mut());
                }
            }
        }

        let mut proc_cleanup = SuspendedProcCleanup {
            h_proc: pi.hProcess,
            h_thread: pi.hThread,
            terminate_on_drop: true,
        };
        let pid = pi.dwProcessId;

        // 4. Pre-ResumeThread Job Object binding & IsProcessInJob verification.
        unsafe { AssignProcessToJobObject(job.handle(), pi.hProcess) }.map_err(|e| {
            KillSwitchError::NativeOsError(format!(
                "Fail-closed: AssignProcessToJobObject failed for AppContainer PID {pid}: {e}"
            ))
        })?;

        let mut in_job = BOOL(0);
        unsafe { IsProcessInJob(pi.hProcess, job.handle(), &mut in_job) }.map_err(|e| {
            KillSwitchError::NativeOsError(format!(
                "Fail-closed: IsProcessInJob failed for AppContainer PID {pid}: {e}"
            ))
        })?;
        if !in_job.as_bool() {
            return Err(KillSwitchError::NativeOsError(format!(
                "Fail-closed: AppContainer PID {pid} failed IsProcessInJob before ResumeThread"
            )));
        }

        // 5. Verify kernel token is genuinely AppContainer-confined BEFORE ResumeThread.
        let mut h_token = HANDLE(std::ptr::null_mut());
        unsafe { OpenProcessToken(pi.hProcess, TOKEN_QUERY, &mut h_token) }.map_err(|e| {
            KillSwitchError::NativeOsError(format!(
                "Fail-closed: OpenProcessToken failed for PID {pid}: {e}"
            ))
        })?;
        let mut is_ac: u32 = 0;
        let mut ret_len: u32 = 0;
        let tok_res = unsafe {
            GetTokenInformation(
                h_token,
                TokenIsAppContainer,
                Some((&mut is_ac as *mut u32).cast()),
                std::mem::size_of::<u32>() as u32,
                &mut ret_len,
            )
        };
        unsafe {
            let _ = CloseHandle(h_token);
        }
        tok_res.map_err(|e| {
            KillSwitchError::NativeOsError(format!(
                "Fail-closed: GetTokenInformation(TokenIsAppContainer) failed for PID {pid}: {e}"
            ))
        })?;
        if is_ac == 0 {
            return Err(KillSwitchError::NativeOsError(format!(
                "Fail-closed: PID {pid} token reported TokenIsAppContainer == 0 before ResumeThread"
            )));
        }

        // 6. Register PID cleanly before resuming execution.
        TrackedAgentTreeRegistry::global().register_agent_root_with_sandbox(
            pid,
            config.agent_id.clone(),
            config.agent_id.clone(),
            Some(sandbox_id.to_string()),
        );

        let prev_suspend = unsafe { ResumeThread(pi.hThread) };
        if prev_suspend == u32::MAX {
            TrackedAgentTreeRegistry::global().unregister_pid(pid);
            return Err(KillSwitchError::NativeOsError(format!(
                "Fail-closed: ResumeThread failed for AppContainer PID {pid}"
            )));
        }

        // Transfer ownership cleanly: h_thread closes via Drop, h_proc stays open on SandboxedAgentProcess.
        proc_cleanup.terminate_on_drop = false;
        drop(proc_cleanup);
        profile_rollback.active = false;

        Ok(SandboxedAgentProcess {
            pid,
            sandbox_id: sandbox_id.to_string(),
            isolation_mode: "win32_appcontainer_job_object",
            is_appcontainer: true,
            process_handle_raw: pi.hProcess.0 as usize,
            appcontainer_profile: Some(profile_name),
            job: Some(job),
        })
    }
}

/// Cross-OS kernel-confined agent launch entrypoint:
/// - Windows: capabilityless AppContainer + Job Object (`EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED`)
/// - Linux: cgroup v2 + fail-closed Landlock LSM + `PR_SET_NO_NEW_PRIVS` + `seccomp-bpf` (WS4.2)
/// - macOS: Darwin SBPL `sandbox-exec` wrapper + descendant tracking (WS4.3)
pub fn spawn_sandboxed_agent_process(
    config: SandboxedAgentConfig,
) -> KillSwitchResult<SandboxedAgentProcess> {
    let seq = SANDBOX_SEQ.fetch_add(1, Ordering::Relaxed);
    let sandbox_id = format!("ks-sandbox-{seq}");

    #[cfg(target_os = "windows")]
    {
        WindowsAppContainerSandbox::spawn(&config, &sandbox_id)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let mut cmd = Command::new(&config.program);
        cmd.args(&config.args);
        if let Some(ref cwd) = config.current_dir {
            cmd.current_dir(cwd);
        }

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::CommandExt;
            use std::path::{Path, PathBuf};

            let mut read_only = vec![
                PathBuf::from("/usr"),
                PathBuf::from("/bin"),
                PathBuf::from("/sbin"),
                PathBuf::from("/lib"),
                PathBuf::from("/lib64"),
                PathBuf::from("/lib32"),
                PathBuf::from("/etc"),
                PathBuf::from("/dev/null"),
                PathBuf::from("/dev/zero"),
                PathBuf::from("/dev/urandom"),
            ];
            for r in &config.readable_paths {
                read_only.push(r.clone());
            }
            let prog_path = Path::new(&config.program);
            if prog_path.is_absolute() && prog_path.exists() {
                read_only.push(prog_path.to_path_buf());
            }
            if let Some(ref cwd) = config.current_dir {
                if !config.writable_paths.contains(cwd) {
                    read_only.push(cwd.clone());
                }
            }
            let ll_cfg = crate::landlock::LandlockSandboxConfig {
                read_only_paths: read_only,
                read_write_paths: config.writable_paths.clone(),
                allowed_tcp_ports: Vec::new(),
                strict: true,
            };
            let prepared =
                crate::landlock::PreparedLinuxSandbox::prepare(&ll_cfg, config.allow_network)?;
            unsafe {
                cmd.pre_exec(move || prepared.apply_in_pre_exec());
            }
        }

        let child = cmd.spawn()?;
        let pid = child.id();
        TrackedAgentTreeRegistry::global().register_agent_root_with_sandbox(
            pid,
            config.agent_id.clone(),
            config.agent_id.clone(),
            Some(sandbox_id.clone()),
        );
        #[cfg(target_os = "linux")]
        let cgroup = {
            let mut cg_cfg = JobSandboxConfig::new(sandbox_id.clone(), config.agent_id.clone());
            cg_cfg.active_process_limit = config.active_process_limit;
            cg_cfg.kill_on_close = config.kill_on_close;
            match LinuxCgroupSandbox::create(cg_cfg) {
                Ok(cg) => {
                    let _ = cg.attach_existing_pid(pid);
                    Some(cg)
                }
                Err(_) => None,
            }
        };
        #[cfg(target_os = "linux")]
        let isolation_mode = "linux_cgroup_landlock_seccomp";
        #[cfg(not(target_os = "linux"))]
        let isolation_mode = "unix_confined_subtree";
        Ok(SandboxedAgentProcess {
            pid,
            sandbox_id,
            isolation_mode,
            is_appcontainer: false,
            child: Some(child),
            #[cfg(target_os = "linux")]
            cgroup,
        })
    }
}

// =============================================================================
// Linux cgroups v2 Sandbox
// =============================================================================

#[cfg(target_os = "linux")]
pub struct LinuxCgroupSandbox {
    cgroup_dir: std::path::PathBuf,
}

#[cfg(target_os = "linux")]
impl LinuxCgroupSandbox {
    const SLICE_ROOT: &'static str = "/sys/fs/cgroup/killswitch.slice";

    fn sanitize_id(id: &str) -> String {
        let s: String = id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        if s.is_empty() {
            "default".to_string()
        } else {
            s
        }
    }

    /// Attempts to create `/sys/fs/cgroup/killswitch.slice/<sandbox_id>`.
    pub fn create(config: JobSandboxConfig) -> KillSwitchResult<Self> {
        let slice_path = std::path::Path::new(Self::SLICE_ROOT);
        let dir_name = Self::sanitize_id(&config.sandbox_id);
        let cgroup_dir = slice_path.join(dir_name);
        std::fs::create_dir_all(&cgroup_dir).map_err(|e| {
            KillSwitchError::NativeOsError(format!(
                "Failed to create cgroup v2 dir '{}': {e}",
                cgroup_dir.display()
            ))
        })?;
        let freeze_file = cgroup_dir.join("cgroup.freeze");
        if !freeze_file.exists() {
            return Err(KillSwitchError::NativeOsError(format!(
                "cgroup.freeze missing under '{}'",
                cgroup_dir.display()
            )));
        }
        if let Some(limit) = config.active_process_limit {
            let pids_max = cgroup_dir.join("pids.max");
            if pids_max.exists() {
                let _ = std::fs::write(&pids_max, limit.max(1).to_string());
            }
        }
        Ok(Self { cgroup_dir })
    }

    pub fn attach_existing_pid(&self, pid: u32) -> KillSwitchResult<()> {
        let procs_file = self.cgroup_dir.join("cgroup.procs");
        std::fs::write(&procs_file, pid.to_string()).map_err(|e| {
            KillSwitchError::NativeOsError(format!(
                "Failed writing PID {pid} to '{}': {e}",
                procs_file.display()
            ))
        })
    }

    pub fn freeze(&self) -> KillSwitchResult<()> {
        let freeze_file = self.cgroup_dir.join("cgroup.freeze");
        std::fs::write(&freeze_file, "1").map_err(|e| {
            KillSwitchError::NativeOsError(format!("Failed writing '1' to cgroup.freeze: {e}"))
        })?;
        for _ in 0..10 {
            if let Ok(state) = std::fs::read_to_string(&freeze_file) {
                if state.trim() == "1" {
                    return Ok(());
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Ok(())
    }

    pub fn thaw(&self) -> KillSwitchResult<()> {
        let freeze_file = self.cgroup_dir.join("cgroup.freeze");
        std::fs::write(&freeze_file, "0").map_err(|e| {
            KillSwitchError::NativeOsError(format!("Failed writing '0' to cgroup.freeze: {e}"))
        })
    }

    pub fn member_pids(&self) -> KillSwitchResult<Vec<u32>> {
        let procs_file = self.cgroup_dir.join("cgroup.procs");
        let content = std::fs::read_to_string(&procs_file).map_err(|e| {
            KillSwitchError::NativeOsError(format!("Failed reading cgroup.procs: {e}"))
        })?;
        Ok(content
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .collect())
    }

    pub fn terminate(&self) -> KillSwitchResult<()> {
        let kill_file = self.cgroup_dir.join("cgroup.kill");
        if kill_file.exists() && std::fs::write(&kill_file, "1").is_ok() {
            return Ok(());
        }
        for pid in self.member_pids()? {
            unsafe {
                let _ = libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct ChildCleanupGuard {
        children: Vec<Child>,
    }

    impl ChildCleanupGuard {
        fn new() -> Self {
            Self {
                children: Vec::new(),
            }
        }
        fn push(&mut self, child: Child) {
            self.children.push(child);
        }
    }

    impl Drop for ChildCleanupGuard {
        fn drop(&mut self) {
            for child in &mut self.children {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_job_sandbox_spawns_suspended_verifies_membership_and_contains_descendants() {
        let mut cmd = Command::new("cmd.exe");
        cmd.args(["/C", "cmd.exe /C ping -n 25 127.0.0.1 >nul"]);
        let mut confined = spawn_confined_process(&mut cmd, "test-agent-win")
            .expect("spawn_confined_process must assign suspended child into job and resume");
        let root_pid = confined.pid();

        // Spawn an uninvolved sibling process OUTSIDE the Job Object to confirm selectivity.
        let mut sibling_cmd = Command::new("cmd.exe");
        sibling_cmd.args(["/C", "ping -n 25 127.0.0.1 >nul"]);
        let sibling_child = sibling_cmd
            .spawn()
            .expect("uninvolved sibling should spawn cleanly");
        let sibling_pid = sibling_child.id();
        let mut sibling_guard = ChildCleanupGuard::new();
        sibling_guard.push(sibling_child);

        let mut members = Vec::new();
        for _ in 0..40 {
            members = confined.member_pids().unwrap_or_default();
            if members.len() >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        assert!(
            members.contains(&root_pid),
            "Root PID {root_pid} must be inside Job Object: {members:?}"
        );
        assert!(
            members.len() >= 2,
            "Expected spawned nested descendant inside Job Object, got {members:?}"
        );
        assert!(
            !members.contains(&sibling_pid),
            "Uninvolved sibling PID {sibling_pid} must NOT appear in agent Job Object"
        );

        let freezer = NativeProcessFreezer::new();
        let job = confined.job.as_ref().expect("Windows job handle present");
        let report = job
            .freeze_members(&freezer)
            .expect("Job freeze_members must succeed");
        assert!(report.frozen_pids.len() >= 2);
        assert!(!report.frozen_pids.contains(&sibling_pid));

        confined
            .terminate(0)
            .expect("TerminateJobObject must cleanly kill entire subtree");
    }

    #[cfg(unix)]
    fn is_unix_pid_stopped(pid: u32) -> bool {
        #[cfg(target_os = "linux")]
        {
            if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                if let Some(after_comm) = stat.rsplit(") ").next() {
                    return after_comm.starts_with("T ") || after_comm.starts_with("t ");
                }
            }
            false
        }
        #[cfg(target_os = "macos")]
        {
            if let Ok(out) = Command::new("ps")
                .args(["-o", "state=", "-p", &pid.to_string()])
                .output()
            {
                let state = String::from_utf8_lossy(&out.stdout);
                return state.trim().starts_with('T');
            }
            false
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let _ = pid;
            false
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_unix_subtree_freeze_halts_nested_descendants_while_sparing_sibling() {
        let mut guard = ChildCleanupGuard::new();

        let agent_root = Command::new("sh")
            .args(["-c", "sleep 20 & sleep 20"])
            .spawn()
            .expect("agent sh subtree must spawn");
        let root_pid = agent_root.id();
        guard.push(agent_root);

        let sibling = Command::new("sleep")
            .arg("20")
            .spawn()
            .expect("sibling sleep must spawn");
        let sibling_pid = sibling.id();
        guard.push(sibling);

        let mut descendants = Vec::new();
        for _ in 0..40 {
            descendants = enumerate_live_descendants(root_pid);
            if descendants.len() >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        assert!(
            descendants.contains(&root_pid) && descendants.len() >= 2,
            "Expected agent root {root_pid} and spawned child, got {descendants:?}"
        );
        assert!(
            !descendants.contains(&sibling_pid),
            "Sibling {sibling_pid} must never appear in agent descendants"
        );

        let freezer = NativeProcessFreezer::new();
        let report = freeze_process_subtree(root_pid, &freezer)
            .expect("freeze_process_subtree must halt agent subtree");
        assert!(
            report.frozen_pids.len() >= 2,
            "Expected root and descendant PIDs frozen, got {:?}",
            report
        );
        assert_eq!(report.residual_unfrozen_children, 0);
        assert!(!report.frozen_pids.contains(&sibling_pid));

        for &fpid in &report.frozen_pids {
            let mut observed_stopped = false;
            for _ in 0..20 {
                if is_unix_pid_stopped(fpid) {
                    observed_stopped = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            assert!(
                observed_stopped,
                "Expected frozen PID {fpid} to enter kernel Stopped ('T') state"
            );
        }
        assert!(
            !is_unix_pid_stopped(sibling_pid),
            "Uninvolved sibling PID {sibling_pid} must remain runnable"
        );

        let _ = resume_process_subtree(root_pid, &freezer);
        for &pid in &report.frozen_pids {
            unsafe {
                let _ = libc::kill(pid as libc::pid_t, libc::SIGKILL);
            }
            TrackedAgentTreeRegistry::global().unregister_pid(pid);
        }
        TrackedAgentTreeRegistry::global().unregister_pid(root_pid);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_appcontainer_sandbox_confines_and_rolls_back_cleanly() {
        let mut cfg = SandboxedAgentConfig::new("test-ac-agent", "cmd.exe");
        cfg.args = vec!["/C".to_string(), "ping -n 25 127.0.0.1 >nul".to_string()];
        cfg.active_process_limit = Some(8);

        let mut proc_handle = spawn_sandboxed_agent_process(cfg)
            .expect("Windows AppContainer spawn must confine cmd.exe inside Job Object");
        assert!(proc_handle.is_appcontainer);
        assert_eq!(proc_handle.isolation_mode, "win32_appcontainer_job_object");
        assert!(proc_handle.pid() > 4);

        let members = proc_handle.member_pids().unwrap_or_default();
        assert!(
            members.contains(&proc_handle.pid()),
            "AppContainer PID {} must be bound in Job Object: {:?}",
            proc_handle.pid(),
            members
        );

        proc_handle
            .terminate(0)
            .expect("AppContainer sandbox termination & profile cleanup must succeed");

        // Verify fail-closed cleanup on failed CreateProcessW launch
        let mut bad_cfg = SandboxedAgentConfig::new(
            "test-ac-fail",
            r"C:\NonExistent\KillSwitch\no_such_agent_binary_12345.exe",
        );
        bad_cfg.args = vec!["--help".to_string()];
        let err = spawn_sandboxed_agent_process(bad_cfg);
        assert!(err.is_err(), "Nonexistent binary must fail closed");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_sandboxed_agent_enforces_landlock_and_seccomp_bpf() {
        let base = std::env::temp_dir().join(format!("ks-linux-ll-{}", std::process::id()));
        let allowed_dir = base.join("allowed");
        let forbidden_dir = base.join("forbidden");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&allowed_dir).unwrap();
        std::fs::create_dir_all(&forbidden_dir).unwrap();

        // 1. Write inside explicit writable_paths succeeds
        let allowed_file = allowed_dir.join("ok.txt");
        let mut ok_cfg = SandboxedAgentConfig::new("test-ll-ok", "sh");
        ok_cfg.args = vec![
            "-c".to_string(),
            format!("printf confined > '{}'", allowed_file.display()),
        ];
        ok_cfg.writable_paths = vec![allowed_dir.clone()];
        let mut ok_proc = spawn_sandboxed_agent_process(ok_cfg)
            .expect("Linux Landlock + seccomp spawn must succeed");
        assert_eq!(ok_proc.isolation_mode, "linux_cgroup_landlock_seccomp");
        let code = ok_proc.wait_exit_code().unwrap();
        assert_eq!(code, 0, "Write inside allowed Landlock path must succeed");
        assert_eq!(std::fs::read_to_string(&allowed_file).unwrap(), "confined");

        // 2. Write outside writable_paths (forbidden sibling dir) fails closed with EACCES
        let escape_file = forbidden_dir.join("escape.txt");
        let mut deny_cfg = SandboxedAgentConfig::new("test-ll-deny", "sh");
        deny_cfg.args = vec![
            "-c".to_string(),
            format!("printf escaped > '{}' 2>/dev/null", escape_file.display()),
        ];
        deny_cfg.writable_paths = vec![allowed_dir.clone()];
        let mut deny_proc = spawn_sandboxed_agent_process(deny_cfg).unwrap();
        let deny_code = deny_proc.wait_exit_code().unwrap();
        assert_ne!(
            deny_code, 0,
            "Write outside Landlock writable_paths must fail"
        );
        assert!(
            !escape_file.exists(),
            "Forbidden escape file must not exist"
        );

        // 3. Seccomp-BPF blocks unshare breakout + AF_INET sockets when allow_network == false
        if std::path::Path::new("/usr/bin/python3").exists() {
            let mut net_cfg = SandboxedAgentConfig::new("test-seccomp-net", "/usr/bin/python3");
            net_cfg.args = vec![
                "-c".to_string(),
                "import errno, socket, sys\ntry:\n socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n sys.exit(2)\nexcept OSError as e:\n sys.exit(0 if e.errno == errno.EPERM else 3)".to_string(),
            ];
            let mut net_proc = spawn_sandboxed_agent_process(net_cfg).unwrap();
            assert_eq!(
                net_proc.wait_exit_code().unwrap(),
                0,
                "Seccomp-BPF must reject socket(AF_INET) with EPERM"
            );
        }

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn test_format_windows_command_line_quoting() {
        let cmdline = format_windows_command_line(
            r"C:\Program Files\Agent\agent.exe",
            &[
                "--flag".to_string(),
                "value with spaces".to_string(),
                r#"quoted "arg"\"#.to_string(),
            ],
        );
        assert_eq!(
            cmdline,
            r#""C:\Program Files\Agent\agent.exe" --flag "value with spaces" "quoted \"arg\"\\""#
        );
    }
}
