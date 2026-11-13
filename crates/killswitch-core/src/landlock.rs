//! Linux Native Isolation, Landlock LSM Sandboxing, Netlink Sockets, and /proc/net/tcp Parser.
//!
//! Provides zero-CLI network and filesystem containment on Linux:
//! - Landlock LSM syscalls: `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`.
//! - Raw Netlink sockets: `libc::socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)`.
//! - Standalone socket inspection: Pure-Rust parser for `/proc/net/tcp` and `/proc/net/tcp6`.

#[cfg(target_os = "linux")]
use crate::wfp::is_authorized_self_diagnostic;
use crate::wfp::{
    sanitize_firewall_preserved_ports, QUARANTINE_BLOCKED_DISCOVERY_PORTS,
    QUARANTINE_BLOCKED_LATERAL_PORTS, QUARANTINE_BLOCKED_LOOPBACK_PROXY_PORTS,
};
use killswitch_types::{
    IsolationReceipt, KillSwitchError, NetworkIsolationEngine, NetworkIsolator,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::debug;
#[cfg(target_os = "linux")]
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// 1. Landlock LSM Syscall Bindings & Definitions
// ---------------------------------------------------------------------------

pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
pub const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
pub const LANDLOCK_RULE_NET_PORT: u32 = 2;

// Syscall numbers (Linux x86_64 and aarch64 standard)
pub const SYS_LANDLOCK_CREATE_RULESET: i64 = 444;
pub const SYS_LANDLOCK_ADD_RULE: i64 = 445;
pub const SYS_LANDLOCK_RESTRICT_SELF: i64 = 446;

// Filesystem access flags
pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
pub const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
pub const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
pub const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
pub const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
pub const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
pub const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
pub const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13; // ABI >= 2
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14; // ABI >= 3

// Network access flags (ABI >= 4, Linux 6.7+)
pub const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LandlockRulesetAttr {
    pub handled_access_fs: u64,
    pub handled_access_net: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LandlockPathBeneathAttr {
    pub allowed_access: u64,
    pub parent_fd: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LandlockNetPortAttr {
    pub allowed_access: u64,
    pub port: u64,
}

/// Query Landlock ABI version supported by the running Linux kernel.
pub fn get_landlock_abi_version() -> Result<u32, KillSwitchError> {
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                std::ptr::null::<u8>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if ret >= 0 {
            Ok(ret as u32)
        } else {
            Err(KillSwitchError::LandlockUnsupported)
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(KillSwitchError::LandlockUnsupported)
    }
}

/// Configuration builder for Landlock filesystem & network sandbox.
#[derive(Debug, Clone)]
pub struct LandlockSandboxConfig {
    pub read_only_paths: Vec<PathBuf>,
    pub read_write_paths: Vec<PathBuf>,
    pub allowed_tcp_ports: Vec<u16>,
    pub strict: bool,
}

impl Default for LandlockSandboxConfig {
    fn default() -> Self {
        Self {
            read_only_paths: vec![
                PathBuf::from("/usr"),
                PathBuf::from("/lib"),
                PathBuf::from("/lib64"),
                PathBuf::from("/etc"),
            ],
            read_write_paths: vec![PathBuf::from("/tmp")],
            allowed_tcp_ports: vec![3030],
            strict: false,
        }
    }
}

/// Applies Landlock containment to the current calling process.
pub fn apply_landlock_sandbox(config: &LandlockSandboxConfig) -> Result<(), KillSwitchError> {
    #[cfg(target_os = "linux")]
    {
        let abi = match get_landlock_abi_version() {
            Ok(v) => v,
            Err(e) => {
                if config.strict {
                    return Err(e);
                }
                warn!("Landlock LSM unsupported on this kernel; skipping Landlock confinement.");
                return Ok(());
            }
        };

        let mut fs_flags = LANDLOCK_ACCESS_FS_EXECUTE
            | LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_READ_FILE
            | LANDLOCK_ACCESS_FS_READ_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_MAKE_CHAR
            | LANDLOCK_ACCESS_FS_MAKE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_REG
            | LANDLOCK_ACCESS_FS_MAKE_SOCK
            | LANDLOCK_ACCESS_FS_MAKE_FIFO
            | LANDLOCK_ACCESS_FS_MAKE_BLOCK
            | LANDLOCK_ACCESS_FS_MAKE_SYM;

        if abi >= 2 {
            fs_flags |= LANDLOCK_ACCESS_FS_REFER;
        }
        if abi >= 3 {
            fs_flags |= LANDLOCK_ACCESS_FS_TRUNCATE;
        }

        let net_flags = if abi >= 4 {
            LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
        } else {
            0
        };

        let attr = LandlockRulesetAttr {
            handled_access_fs: fs_flags,
            handled_access_net: net_flags,
        };

        let attr_size = if abi >= 4 {
            std::mem::size_of::<LandlockRulesetAttr>()
        } else {
            std::mem::size_of::<u64>()
        };

        let ruleset_fd = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                &attr as *const _ as *const libc::c_void,
                attr_size,
                0u32,
            )
        };

        if ruleset_fd < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if config.strict {
                return Err(KillSwitchError::LandlockRulesetCreateFailed { errno });
            }
            warn!("Failed to create Landlock ruleset (errno {}).", errno);
            return Ok(());
        }

        let ruleset_fd = ruleset_fd as i32;

        // Add Read-Only path rules (strict: bail on add_rule error if strict mode)
        for path in &config.read_only_paths {
            if path.exists() {
                if let Err(e) = add_path_rule(ruleset_fd, path, false, abi) {
                    if config.strict {
                        unsafe {
                            libc::close(ruleset_fd);
                        }
                        return Err(e);
                    }
                }
            }
        }

        // Add Read-Write path rules
        for path in &config.read_write_paths {
            if path.exists() {
                if let Err(e) = add_path_rule(ruleset_fd, path, true, abi) {
                    if config.strict {
                        unsafe {
                            libc::close(ruleset_fd);
                        }
                        return Err(e);
                    }
                }
            }
        }

        // Add Net Port rules if supported (ABI >= 4)
        if abi >= 4 {
            for &port in &config.allowed_tcp_ports {
                let net_attr = LandlockNetPortAttr {
                    allowed_access: LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
                    port: port as u64,
                };
                unsafe {
                    libc::syscall(
                        SYS_LANDLOCK_ADD_RULE,
                        ruleset_fd,
                        LANDLOCK_RULE_NET_PORT,
                        &net_attr as *const _ as *const libc::c_void,
                        0u32,
                    );
                }
            }
        }

        // MANDATORY: PR_SET_NO_NEW_PRIVS before restrict_self
        let prctl_ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if prctl_ret != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if config.strict {
                unsafe {
                    libc::close(ruleset_fd);
                }
                return Err(KillSwitchError::LandlockRestrictSelfFailed { errno });
            }
            warn!("prctl(PR_SET_NO_NEW_PRIVS) returned errno {}", errno);
        }

        let restrict_ret = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32) };
        unsafe {
            libc::close(ruleset_fd);
        }

        if restrict_ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if config.strict {
                return Err(KillSwitchError::LandlockRestrictSelfFailed { errno });
            }
            warn!("Landlock restrict_self failed with errno {}", errno);
            return Ok(());
        }

        info!("🟢 [Landlock] Kernel sandbox successfully locked down.");
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn build_landlock_ruleset_fd(
    config: &LandlockSandboxConfig,
    enforce_net: bool,
) -> Result<Option<i32>, KillSwitchError> {
    let abi = match get_landlock_abi_version() {
        Ok(v) => v,
        Err(e) => {
            if config.strict {
                return Err(e);
            }
            return Ok(None);
        }
    };

    let mut fs_flags = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;

    if abi >= 2 {
        fs_flags |= LANDLOCK_ACCESS_FS_REFER;
    }
    if abi >= 3 {
        fs_flags |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }

    let net_flags = if abi >= 4 && enforce_net {
        LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
    } else {
        0
    };

    let attr = LandlockRulesetAttr {
        handled_access_fs: fs_flags,
        handled_access_net: net_flags,
    };

    let attr_size = if abi >= 4 && enforce_net {
        std::mem::size_of::<LandlockRulesetAttr>()
    } else {
        std::mem::size_of::<u64>()
    };

    let ruleset_fd = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const _ as *const libc::c_void,
            attr_size,
            0u32,
        )
    };
    if ruleset_fd < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if config.strict {
            return Err(KillSwitchError::LandlockRulesetCreateFailed { errno });
        }
        return Ok(None);
    }

    let fd = ruleset_fd as i32;
    for path in &config.read_only_paths {
        if path.exists() {
            if let Err(e) = add_path_rule(fd, path, false, abi) {
                if config.strict {
                    unsafe {
                        libc::close(fd);
                    }
                    return Err(e);
                }
            }
        }
    }
    for path in &config.read_write_paths {
        if path.exists() {
            if let Err(e) = add_path_rule(fd, path, true, abi) {
                if config.strict {
                    unsafe {
                        libc::close(fd);
                    }
                    return Err(e);
                }
            }
        }
    }
    if enforce_net && abi >= 4 {
        for &port in &config.allowed_tcp_ports {
            let net_attr = LandlockNetPortAttr {
                allowed_access: LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP,
                port: port as u64,
            };
            let ret = unsafe {
                libc::syscall(
                    SYS_LANDLOCK_ADD_RULE,
                    fd,
                    LANDLOCK_RULE_NET_PORT,
                    &net_attr as *const _ as *const libc::c_void,
                    0u32,
                )
            };
            if ret < 0 && config.strict {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                unsafe {
                    libc::close(fd);
                }
                return Err(KillSwitchError::LandlockAddRuleFailed {
                    path: PathBuf::from(format!("tcp-port:{port}")),
                    errno,
                });
            }
        }
    }
    Ok(Some(fd))
}

#[cfg(target_os = "linux")]
fn add_path_rule(
    ruleset_fd: i32,
    path: &Path,
    writable: bool,
    abi: u32,
) -> Result<(), KillSwitchError> {
    use std::os::unix::io::AsRawFd;
    let file = std::fs::File::open(path).map_err(|e| KillSwitchError::LandlockAddRuleFailed {
        path: path.to_path_buf(),
        errno: e.raw_os_error().unwrap_or(0),
    })?;
    let meta = file.metadata().ok();
    let is_dir = meta.as_ref().is_some_and(|m| m.is_dir());
    let is_regular_file = meta.as_ref().is_some_and(|m| m.is_file());

    let allowed_access = if is_dir {
        let mut dir_read =
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE;
        if writable {
            dir_read |= LANDLOCK_ACCESS_FS_WRITE_FILE
                | LANDLOCK_ACCESS_FS_REMOVE_DIR
                | LANDLOCK_ACCESS_FS_REMOVE_FILE
                | LANDLOCK_ACCESS_FS_MAKE_REG
                | LANDLOCK_ACCESS_FS_MAKE_DIR
                | LANDLOCK_ACCESS_FS_MAKE_SYM;
            if abi >= 2 {
                dir_read |= LANDLOCK_ACCESS_FS_REFER;
            }
            if abi >= 3 {
                dir_read |= LANDLOCK_ACCESS_FS_TRUNCATE;
            }
        }
        dir_read
    } else {
        // File/device-only flags (directory flags cause EINVAL on non-directory descriptors in Landlock;
        // omit EXECUTE on character devices such as /dev/null and /dev/urandom).
        let mut file_access = LANDLOCK_ACCESS_FS_READ_FILE;
        if is_regular_file {
            file_access |= LANDLOCK_ACCESS_FS_EXECUTE;
        }
        if writable {
            file_access |= LANDLOCK_ACCESS_FS_WRITE_FILE;
            if abi >= 3 {
                file_access |= LANDLOCK_ACCESS_FS_TRUNCATE;
            }
        }
        file_access
    };

    let attr = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd: file.as_raw_fd(),
    };

    let ret = unsafe {
        libc::syscall(
            SYS_LANDLOCK_ADD_RULE,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &attr as *const _ as *const libc::c_void,
            0u32,
        )
    };

    if ret < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        Err(KillSwitchError::LandlockAddRuleFailed {
            path: path.to_path_buf(),
            errno,
        })
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 1b. Pre-Fork Async-Signal-Safe Landlock + Seccomp-BPF Agent Confinement
// ---------------------------------------------------------------------------

pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
pub const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

pub const BPF_LD_W_ABS: u16 = 0x20;
pub const BPF_JMP_JEQ_K: u16 = 0x15;
pub const BPF_RET_K: u16 = 0x06;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_ERRNO_EPERM: u32 = 0x0005_0001;
pub const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

#[inline]
const fn bpf_stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

#[inline]
const fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// Builds a classical cBPF seccomp filter blocking container/namespace escape syscalls
/// (`ptrace`, `process_vm_readv/writev`, `mount`, `umount2`, `pivot_root`, `chroot`, `setns`,
/// `unshare`, `bpf`, `init_module`, `finit_module`, `kexec_load`, `io_uring_setup`, `userfaultfd`,
/// `perf_event_open`, `keyctl`) and, when `allow_network == false`, blocking non-`AF_UNIX` `socket()`
/// and `socketpair()` calls across x86_64 and aarch64.
pub fn build_agent_seccomp_bpf(allow_network: bool) -> Vec<SockFilter> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let (expected_arch, blocked_syscalls, socket_nr, socketpair_nr) = (
        AUDIT_ARCH_X86_64,
        [
            libc::SYS_ptrace as u32,
            libc::SYS_process_vm_readv as u32,
            libc::SYS_process_vm_writev as u32,
            libc::SYS_kexec_load as u32,
            libc::SYS_init_module as u32,
            libc::SYS_finit_module as u32,
            libc::SYS_delete_module as u32,
            libc::SYS_mount as u32,
            libc::SYS_umount2 as u32,
            libc::SYS_pivot_root as u32,
            libc::SYS_chroot as u32,
            libc::SYS_setns as u32,
            libc::SYS_unshare as u32,
            libc::SYS_bpf as u32,
            libc::SYS_perf_event_open as u32,
            libc::SYS_io_uring_setup as u32,
            libc::SYS_userfaultfd as u32,
            libc::SYS_keyctl as u32,
            libc::SYS_add_key as u32,
            libc::SYS_request_key as u32,
        ]
        .as_slice(),
        libc::SYS_socket as u32,
        libc::SYS_socketpair as u32,
    );

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    let (expected_arch, blocked_syscalls, socket_nr, socketpair_nr) = (
        AUDIT_ARCH_AARCH64,
        [
            libc::SYS_ptrace as u32,
            libc::SYS_process_vm_readv as u32,
            libc::SYS_process_vm_writev as u32,
            libc::SYS_kexec_load as u32,
            libc::SYS_init_module as u32,
            libc::SYS_finit_module as u32,
            libc::SYS_delete_module as u32,
            libc::SYS_mount as u32,
            libc::SYS_umount2 as u32,
            libc::SYS_pivot_root as u32,
            libc::SYS_chroot as u32,
            libc::SYS_setns as u32,
            libc::SYS_unshare as u32,
            libc::SYS_bpf as u32,
            libc::SYS_perf_event_open as u32,
            libc::SYS_io_uring_setup as u32,
            libc::SYS_userfaultfd as u32,
            libc::SYS_keyctl as u32,
            libc::SYS_add_key as u32,
            libc::SYS_request_key as u32,
        ]
        .as_slice(),
        libc::SYS_socket as u32,
        libc::SYS_socketpair as u32,
    );

    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    let (expected_arch, blocked_syscalls, socket_nr, socketpair_nr) = (
        AUDIT_ARCH_X86_64,
        // Linux x86_64 canonical syscall numbers for deterministic cross-OS BPF verification
        [
            101u32, 310, 311, 246, 175, 313, 176, 165, 166, 155, 161, 308, 272, 321, 298, 425, 323,
            250, 248, 249,
        ]
        .as_slice(),
        41u32,
        53u32,
    );

    let mut prog = Vec::with_capacity(blocked_syscalls.len() + 14);
    // [0..2]: Enforce exact syscall audit arch to defeat 32-bit/compat int 0x80 ABI bypass
    prog.push(bpf_stmt(BPF_LD_W_ABS, 4));
    prog.push(bpf_jump(BPF_JMP_JEQ_K, expected_arch, 1, 0));
    prog.push(bpf_stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));

    // [3]: Load seccomp_data.nr (offset 0)
    prog.push(bpf_stmt(BPF_LD_W_ABS, 0));

    // Placeholder indices for deny jumps; patched cleanly after trailer emission.
    let mut deny_jump_indices = Vec::with_capacity(blocked_syscalls.len());
    for &sys_nr in blocked_syscalls {
        deny_jump_indices.push(prog.len());
        prog.push(bpf_jump(BPF_JMP_JEQ_K, sys_nr, 0, 0));
    }

    if !allow_network {
        // Inspect socket(domain, ...) and socketpair(domain, ...): permit ONLY AF_UNIX (1).
        prog.push(bpf_jump(BPF_JMP_JEQ_K, socket_nr, 1, 0));
        prog.push(bpf_jump(BPF_JMP_JEQ_K, socketpair_nr, 0, 3));
        prog.push(bpf_stmt(BPF_LD_W_ABS, 16)); // seccomp_data.args[0] low u32
        prog.push(bpf_jump(BPF_JMP_JEQ_K, 1, 1, 0)); // AF_UNIX == 1 on Linux
        prog.push(bpf_stmt(BPF_RET_K, SECCOMP_RET_ERRNO_EPERM));
    }

    prog.push(bpf_stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    let deny_idx = prog.len();
    prog.push(bpf_stmt(BPF_RET_K, SECCOMP_RET_ERRNO_EPERM));

    for idx in deny_jump_indices {
        let offset = (deny_idx - idx - 1) as u8;
        prog[idx].jt = offset;
    }

    prog
}

/// Async-signal-safe prepared Landlock + seccomp-bpf confinement bundle created BEFORE `fork()`,
/// applied strictly via raw syscalls in `CommandExt::pre_exec` with zero heap allocation.
#[cfg(target_os = "linux")]
pub struct PreparedLinuxSandbox {
    ruleset_fd: Option<i32>,
    seccomp_prog: Vec<SockFilter>,
    strict: bool,
}

#[cfg(target_os = "linux")]
impl PreparedLinuxSandbox {
    pub fn prepare(
        config: &LandlockSandboxConfig,
        allow_network: bool,
    ) -> Result<Self, KillSwitchError> {
        let enforce_net = !allow_network || !config.allowed_tcp_ports.is_empty();
        let ruleset_fd = build_landlock_ruleset_fd(config, enforce_net)?;
        if let Some(fd) = ruleset_fd {
            unsafe {
                let _ = libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
        }
        let seccomp_prog = build_agent_seccomp_bpf(allow_network);
        Ok(Self {
            ruleset_fd,
            seccomp_prog,
            strict: config.strict,
        })
    }

    pub fn prepare_seccomp_only(allow_network: bool, strict: bool) -> Self {
        Self {
            ruleset_fd: None,
            seccomp_prog: build_agent_seccomp_bpf(allow_network),
            strict,
        }
    }

    /// Invoked in the child process between `fork()` and `exec()` via `CommandExt::pre_exec`.
    /// Must remain strictly async-signal-safe (raw syscalls / prctl only).
    ///
    /// # Safety
    /// Caller must run inside `pre_exec` (single-threaded child context before `exec`) while
    /// `self` outlives `pre_exec`.
    pub unsafe fn apply_in_pre_exec(&self) -> std::io::Result<()> {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if let Some(fd) = self.ruleset_fd {
            let ret = libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, fd, 0u32);
            let saved_err = std::io::Error::last_os_error();
            let _ = libc::close(fd);
            if ret < 0 && self.strict {
                return Err(saved_err);
            }
        }
        if !self.seccomp_prog.is_empty() {
            let fprog = SockFprog {
                len: self.seccomp_prog.len() as u16,
                filter: self.seccomp_prog.as_ptr(),
            };
            // SECCOMP_MODE_FILTER == 2
            if libc::prctl(libc::PR_SET_SECCOMP, 2, &fprog as *const SockFprog) != 0 {
                let err = std::io::Error::last_os_error();
                if self.strict {
                    return Err(err);
                }
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for PreparedLinuxSandbox {
    fn drop(&mut self) {
        if let Some(fd) = self.ruleset_fd.take() {
            unsafe {
                let _ = libc::close(fd);
            }
        }
    }
}

/// Applies `PR_SET_NO_NEW_PRIVS` + agent `seccomp-bpf` directly to the current process.
pub fn apply_agent_seccomp_bpf(allow_network: bool) -> Result<(), KillSwitchError> {
    #[cfg(target_os = "linux")]
    {
        let prog = build_agent_seccomp_bpf(allow_network);
        let fprog = SockFprog {
            len: prog.len() as u16,
            filter: prog.as_ptr(),
        };
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                return Err(KillSwitchError::LandlockRestrictSelfFailed { errno });
            }
            if libc::prctl(libc::PR_SET_SECCOMP, 2, &fprog as *const SockFprog) != 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                return Err(KillSwitchError::LandlockRestrictSelfFailed { errno });
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = allow_network;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 2. Linux Raw Netlink Socket Isolator & Route Blackholing
// ---------------------------------------------------------------------------

// Netlink Route Constants (linux/rtnetlink.h, linux/netlink.h)
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;

pub const NLM_F_REQUEST: u16 = 0x01;
pub const NLM_F_ACK: u16 = 0x04;
pub const NLM_F_CREATE: u16 = 0x400;
pub const NLM_F_EXCL: u16 = 0x200;
pub const NLM_F_REPLACE: u16 = 0x100;

pub const RTN_UNSPEC: u8 = 0;
pub const RTN_UNICAST: u8 = 1;
pub const RTN_LOCAL: u8 = 2;
pub const RTN_BLACKHOLE: u8 = 6;
pub const RTN_UNREACHABLE: u8 = 7;
pub const RTN_PROHIBIT: u8 = 8;

pub const RT_TABLE_MAIN: u8 = 254;
pub const RT_TABLE_LOCAL: u8 = 255;

pub const RTPROT_BOOT: u8 = 3;
pub const RTPROT_STATIC: u8 = 4;

pub const RT_SCOPE_UNIVERSE: u8 = 0;
pub const RT_SCOPE_NOWHERE: u8 = 255;

pub const RTA_DST: u16 = 1;
pub const RTA_PRIORITY: u16 = 6;
pub const RTA_TABLE: u16 = 15;

// Netlink INET_DIAG Constants (linux/inet_diag.h, linux/sock_diag.h)
pub const NETLINK_INET_DIAG: i32 = 4;
pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
pub const SOCK_DESTROY: u16 = 21;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct NlMsgHdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RtMsg {
    pub rtm_family: u8,
    pub rtm_dst_len: u8,
    pub rtm_src_len: u8,
    pub rtm_tos: u8,
    pub rtm_table: u8,
    pub rtm_protocol: u8,
    pub rtm_scope: u8,
    pub rtm_type: u8,
    pub rtm_flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RtAttr {
    pub rta_len: u16,
    pub rta_type: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SockAddrNl {
    pub nl_family: u16,
    pub nl_pad: u16,
    pub nl_pid: u32,
    pub nl_groups: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct InetDiagSockId {
    pub idiag_sport: u16,
    pub idiag_dport: u16,
    pub idiag_src: [u32; 4],
    pub idiag_dst: [u32; 4],
    pub idiag_if: u32,
    pub idiag_cookie: [u32; 2],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct InetDiagReqV2 {
    pub sdiag_family: u8,
    pub sdiag_protocol: u8,
    pub idiag_ext: u8,
    pub pad: u8,
    pub idiag_states: u32,
    pub id: InetDiagSockId,
}

/// Builds a binary Netlink route blackhole message for IPv4 (0.0.0.0/0) or IPv6 (::/0).
pub fn build_blackhole_route_msg(is_v6: bool, is_delete: bool, priority: u32) -> Vec<u8> {
    let family = if is_v6 {
        #[cfg(target_os = "linux")]
        {
            libc::AF_INET6 as u8
        }
        #[cfg(not(target_os = "linux"))]
        {
            10u8
        }
    } else {
        #[cfg(target_os = "linux")]
        {
            libc::AF_INET as u8
        }
        #[cfg(not(target_os = "linux"))]
        {
            2u8
        }
    };

    let rta_attr_len = std::mem::size_of::<RtAttr>() + std::mem::size_of::<u32>();
    let total_len = std::mem::size_of::<NlMsgHdr>() + std::mem::size_of::<RtMsg>() + rta_attr_len;

    let nlmsg_type = if is_delete {
        RTM_DELROUTE
    } else {
        RTM_NEWROUTE
    };
    let nlmsg_flags = if is_delete {
        NLM_F_REQUEST | NLM_F_ACK
    } else {
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE
    };

    let mut buf = Vec::with_capacity(total_len);

    let hdr = NlMsgHdr {
        nlmsg_len: total_len as u32,
        nlmsg_type,
        nlmsg_flags,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };

    let rt = RtMsg {
        rtm_family: family,
        rtm_dst_len: 0, // 0.0.0.0/0 or ::/0
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: RT_TABLE_MAIN,
        rtm_protocol: RTPROT_STATIC,
        rtm_scope: RT_SCOPE_UNIVERSE,
        rtm_type: RTN_BLACKHOLE,
        rtm_flags: 0,
    };

    let rta = RtAttr {
        rta_len: rta_attr_len as u16,
        rta_type: RTA_PRIORITY,
    };

    unsafe {
        let hdr_bytes = std::slice::from_raw_parts(
            &hdr as *const _ as *const u8,
            std::mem::size_of::<NlMsgHdr>(),
        );
        buf.extend_from_slice(hdr_bytes);

        let rt_bytes =
            std::slice::from_raw_parts(&rt as *const _ as *const u8, std::mem::size_of::<RtMsg>());
        buf.extend_from_slice(rt_bytes);

        let rta_bytes = std::slice::from_raw_parts(
            &rta as *const _ as *const u8,
            std::mem::size_of::<RtAttr>(),
        );
        buf.extend_from_slice(rta_bytes);

        buf.extend_from_slice(&priority.to_ne_bytes());
    }

    buf
}

/// Builds a binary Netlink INET_DIAG SOCK_DESTROY message for an arbitrary IP protocol
/// (`6` = TCP, `17` = UDP, `255` = RAW).
pub fn build_sock_destroy_msg_for_proto(entry: &LinuxSocketEntry, protocol: u8) -> Vec<u8> {
    let family = if entry.is_ipv6 {
        #[cfg(target_os = "linux")]
        {
            libc::AF_INET6 as u8
        }
        #[cfg(not(target_os = "linux"))]
        {
            10u8
        }
    } else {
        #[cfg(target_os = "linux")]
        {
            libc::AF_INET as u8
        }
        #[cfg(not(target_os = "linux"))]
        {
            2u8
        }
    };

    let total_len = std::mem::size_of::<NlMsgHdr>() + std::mem::size_of::<InetDiagReqV2>();

    let hdr = NlMsgHdr {
        nlmsg_len: total_len as u32,
        nlmsg_type: SOCK_DESTROY,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
        nlmsg_seq: 2,
        nlmsg_pid: 0,
    };

    let mut sock_id = InetDiagSockId {
        idiag_sport: entry.local_port.to_be(),
        idiag_dport: entry.remote_port.to_be(),
        idiag_src: [0u32; 4],
        idiag_dst: [0u32; 4],
        idiag_if: 0,
        idiag_cookie: [0xFFFFFFFF, 0xFFFFFFFF], // INET_DIAG_NOCOOKIE
    };

    match entry.local_addr {
        IpAddr::V4(v4) => {
            sock_id.idiag_src[0] = u32::from_ne_bytes(v4.octets());
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            sock_id.idiag_src[0] = u32::from_ne_bytes([o[0], o[1], o[2], o[3]]);
            sock_id.idiag_src[1] = u32::from_ne_bytes([o[4], o[5], o[6], o[7]]);
            sock_id.idiag_src[2] = u32::from_ne_bytes([o[8], o[9], o[10], o[11]]);
            sock_id.idiag_src[3] = u32::from_ne_bytes([o[12], o[13], o[14], o[15]]);
        }
    }

    match entry.remote_addr {
        IpAddr::V4(v4) => {
            sock_id.idiag_dst[0] = u32::from_ne_bytes(v4.octets());
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            sock_id.idiag_dst[0] = u32::from_ne_bytes([o[0], o[1], o[2], o[3]]);
            sock_id.idiag_dst[1] = u32::from_ne_bytes([o[4], o[5], o[6], o[7]]);
            sock_id.idiag_dst[2] = u32::from_ne_bytes([o[8], o[9], o[10], o[11]]);
            sock_id.idiag_dst[3] = u32::from_ne_bytes([o[12], o[13], o[14], o[15]]);
        }
    }

    let req = InetDiagReqV2 {
        sdiag_family: family,
        sdiag_protocol: protocol,
        idiag_ext: 0,
        pad: 0,
        idiag_states: 0xFFFFFFFF,
        id: sock_id,
    };

    let mut buf = Vec::with_capacity(total_len);
    unsafe {
        let hdr_bytes = std::slice::from_raw_parts(
            &hdr as *const _ as *const u8,
            std::mem::size_of::<NlMsgHdr>(),
        );
        buf.extend_from_slice(hdr_bytes);

        let req_bytes = std::slice::from_raw_parts(
            &req as *const _ as *const u8,
            std::mem::size_of::<InetDiagReqV2>(),
        );
        buf.extend_from_slice(req_bytes);
    }
    buf
}

/// Builds a binary Netlink INET_DIAG SOCK_DESTROY message to abort a TCP connection.
pub fn build_sock_destroy_msg(entry: &LinuxSocketEntry) -> Vec<u8> {
    build_sock_destroy_msg_for_proto(entry, 6)
}

#[cfg(target_os = "linux")]
fn send_netlink_route_message(msg: &[u8]) -> Result<(), KillSwitchError> {
    unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE);
        if fd < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::EPERM || errno == libc::EACCES {
                return Err(KillSwitchError::InsufficientPrivileges {
                    details: format!(
                        "Netlink NETLINK_ROUTE socket creation failed: errno {}",
                        errno
                    ),
                    remediation: "Ensure the process is running as root with CAP_NET_ADMIN."
                        .to_string(),
                });
            }
            return Err(KillSwitchError::NetlinkSocketCreateFailed {
                protocol: libc::NETLINK_ROUTE,
                errno,
            });
        }

        let mut sa: libc::sockaddr_nl = std::mem::zeroed();
        sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        sa.nl_pid = 0; // Kernel
        sa.nl_groups = 0;

        let ret = libc::sendto(
            fd,
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
            0,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        );

        if ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            libc::close(fd);
            if errno == libc::EPERM || errno == libc::EACCES {
                return Err(KillSwitchError::InsufficientPrivileges {
                    details: format!(
                        "Netlink route sendto failed with permission denied (errno {})",
                        errno
                    ),
                    remediation: "Ensure the process is running as root with CAP_NET_ADMIN."
                        .to_string(),
                });
            }
            return Err(KillSwitchError::Other(format!(
                "Netlink route sendto failed: errno {}",
                errno
            )));
        }

        // Read Netlink ACK (nlmsgerr) to confirm kernel accepted the route
        let mut resp_buf = [0u8; 1024];
        let recv_len = libc::recv(
            fd,
            resp_buf.as_mut_ptr() as *mut libc::c_void,
            resp_buf.len(),
            0,
        );
        libc::close(fd);

        if recv_len >= std::mem::size_of::<NlMsgHdr>() as isize {
            let hdr = *(resp_buf.as_ptr() as *const NlMsgHdr);
            if hdr.nlmsg_type == 2 {
                // NLMSG_ERROR
                let err_offset = std::mem::size_of::<NlMsgHdr>();
                if recv_len >= (err_offset + 4) as isize {
                    let err_code = i32::from_ne_bytes([
                        resp_buf[err_offset],
                        resp_buf[err_offset + 1],
                        resp_buf[err_offset + 2],
                        resp_buf[err_offset + 3],
                    ]);
                    // err_code == 0 means ACK (success)
                    if err_code != 0 && err_code != -libc::EEXIST && err_code != -libc::ESRCH {
                        let abs_err = err_code.abs();
                        if abs_err == libc::EPERM || abs_err == libc::EACCES {
                            return Err(KillSwitchError::InsufficientPrivileges {
                                details: format!("Kernel Netlink rejected route operation with EPERM/EACCES ({})", abs_err),
                                remediation: "Run with root privileges (sudo) and ensure CAP_NET_ADMIN capability.".to_string(),
                            });
                        }
                        return Err(KillSwitchError::Other(format!(
                            "Kernel Netlink route error: {}",
                            err_code
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn terminate_linux_socket_netlink_proto(
    entry: &LinuxSocketEntry,
    protocol: u8,
) -> Result<(), KillSwitchError> {
    let msg = build_sock_destroy_msg_for_proto(entry, protocol);
    unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_INET_DIAG);
        if fd < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(KillSwitchError::NetlinkSocketCreateFailed {
                protocol: NETLINK_INET_DIAG,
                errno,
            });
        }

        let mut sa: libc::sockaddr_nl = std::mem::zeroed();
        sa.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        sa.nl_pid = 0;
        sa.nl_groups = 0;

        let ret = libc::sendto(
            fd,
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
            0,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        );
        libc::close(fd);

        if ret < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(KillSwitchError::NetlinkSockDestroyFailed {
                four_tuple: format!(
                    "proto={protocol} {}:{} -> {}:{}",
                    entry.local_addr, entry.local_port, entry.remote_addr, entry.remote_port
                ),
                errno,
            });
        }
        Ok(())
    }
}

/// Generates an atomic `nftables` `inet killswitch_quarantine` script with strict default-drop
/// policy, explicit loopback-alias (`127.0.0.2+`), IMDS (`169.254.0.0/16` / `fe80::/10`),
/// DNS/DoT/DHCP/QUIC, loopback proxy (`1080/3128/8080/8888/9050`), and lateral SMB/RPC drops,
/// permitting ONLY exact `127.0.0.1 <-> 127.0.0.1` / `::1 <-> ::1` TCP on sanitized control ports.
pub fn generate_linux_nftables_quarantine_script(
    preserved_ports: &[u16],
    cgroup_paths: &[&str],
    agent_uids: &[u32],
) -> String {
    let ports = sanitize_firewall_preserved_ports(preserved_ports);
    let discovery_csv = QUARANTINE_BLOCKED_DISCOVERY_PORTS
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let proxy_csv = QUARANTINE_BLOCKED_LOOPBACK_PROXY_PORTS
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let lateral_csv = QUARANTINE_BLOCKED_LATERAL_PORTS
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    let mut s = String::from(
        "table inet killswitch_quarantine\n\
delete table inet killswitch_quarantine\n\
table inet killswitch_quarantine {\n\
    chain input {\n\
        type filter hook input priority -150; policy drop;\n\
        ip saddr != 127.0.0.1 ip daddr 127.0.0.0/8 drop\n\
        ip daddr != 127.0.0.1 ip saddr 127.0.0.0/8 drop\n\
        ip daddr 169.254.0.0/16 drop\n\
        ip6 daddr fe80::/10 drop\n",
    );
    s.push_str(&format!(
        "        tcp dport {{ {discovery_csv} }} drop\n\
        udp dport {{ {discovery_csv}, 443 }} drop\n\
        tcp dport {{ {proxy_csv} }} drop\n\
        tcp dport {{ {lateral_csv} }} drop\n"
    ));
    for &port in &ports {
        s.push_str(&format!(
            "        iifname \"lo\" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp dport {port} accept\n\
        iifname \"lo\" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport {port} accept\n\
        iifname \"lo\" ip6 saddr ::1 ip6 daddr ::1 tcp dport {port} accept\n\
        iifname \"lo\" ip6 saddr ::1 ip6 daddr ::1 tcp sport {port} accept\n"
        ));
    }
    s.push_str(
        "    }\n\
    chain output {\n\
        type filter hook output priority -150; policy drop;\n",
    );
    for cg in cgroup_paths {
        let clean: String = cg
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
            .collect();
        if !clean.is_empty() {
            s.push_str(&format!(
                "        socket cgroupv2 level 1 \"{clean}\" drop\n"
            ));
        }
    }
    for &uid in agent_uids {
        s.push_str(&format!("        meta skuid {uid} drop\n"));
    }
    s.push_str(&format!(
        "        ip saddr != 127.0.0.1 ip daddr 127.0.0.0/8 drop\n\
        ip daddr != 127.0.0.1 ip saddr 127.0.0.0/8 drop\n\
        ip daddr 169.254.0.0/16 drop\n\
        ip6 daddr fe80::/10 drop\n\
        tcp dport {{ {discovery_csv} }} drop\n\
        udp dport {{ {discovery_csv}, 443 }} drop\n\
        tcp dport {{ {proxy_csv} }} drop\n\
        tcp dport {{ {lateral_csv} }} drop\n"
    ));
    for &port in &ports {
        s.push_str(&format!(
            "        oifname \"lo\" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp dport {port} accept\n\
        oifname \"lo\" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp sport {port} accept\n\
        oifname \"lo\" ip6 saddr ::1 ip6 daddr ::1 tcp dport {port} accept\n\
        oifname \"lo\" ip6 saddr ::1 ip6 daddr ::1 tcp sport {port} accept\n"
        ));
    }
    s.push_str("    }\n}\n");
    s
}

#[cfg(target_os = "linux")]
fn find_nft_binary() -> Option<&'static str> {
    for candidate in ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "nft"] {
        if candidate == "nft" || Path::new(candidate).exists() {
            return Some(candidate);
        }
    }
    None
}

/// Atomically installs `table inet killswitch_quarantine` via `nft -f -` and performs
/// mandatory readback verification via `nft list table inet killswitch_quarantine`.
pub fn install_linux_nftables_quarantine(
    preserved_ports: &[u16],
    cgroup_paths: &[&str],
    agent_uids: &[u32],
) -> Result<String, KillSwitchError> {
    let script =
        generate_linux_nftables_quarantine_script(preserved_ports, cgroup_paths, agent_uids);
    #[cfg(target_os = "linux")]
    {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let nft_bin = find_nft_binary().ok_or_else(|| {
            KillSwitchError::NativeOsError(
                "nftables binary (nft) not found on Linux host".to_string(),
            )
        })?;
        let mut child = Command::new(nft_bin)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                KillSwitchError::NativeOsError(format!("Failed to invoke {nft_bin}: {e}"))
            })?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(script.as_bytes()).map_err(|e| {
                KillSwitchError::NativeOsError(format!(
                    "Failed writing nftables script to stdin: {e}"
                ))
            })?;
        }
        let out = child.wait_with_output().map_err(|e| {
            KillSwitchError::NativeOsError(format!("Failed waiting on nft -f -: {e}"))
        })?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(KillSwitchError::NativeOsError(format!(
                "nft -f - failed with status {}: {}",
                out.status,
                stderr.trim()
            )));
        }

        // Mandatory readback verification
        let readback = Command::new(nft_bin)
            .args(["list", "table", "inet", "killswitch_quarantine"])
            .output()
            .map_err(|e| {
                KillSwitchError::NativeOsError(format!("nft readback check failed: {e}"))
            })?;
        let body = String::from_utf8_lossy(&readback.stdout);
        if !readback.status.success()
            || !body.contains("chain input")
            || !body.contains("chain output")
        {
            return Err(KillSwitchError::NativeOsError(format!(
                "nftables readback verification failed for inet killswitch_quarantine: {}",
                String::from_utf8_lossy(&readback.stderr).trim()
            )));
        }
        info!("🔒 [LinuxNetlinkIsolator] Installed and readback-verified inet killswitch_quarantine nftables policy.");
    }
    Ok(script)
}

/// Removes `table inet killswitch_quarantine` without touching unrelated host nftables tables.
pub fn remove_linux_nftables_quarantine() -> Result<(), KillSwitchError> {
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;
        if let Some(nft_bin) = find_nft_binary() {
            let _ = Command::new(nft_bin)
                .args(["delete", "table", "inet", "killswitch_quarantine"])
                .output();
        }
    }
    Ok(())
}

/// Installs IPv4 (0.0.0.0/0) and IPv6 (::/0) RTN_BLACKHOLE routes via Netlink NETLINK_ROUTE.
pub fn install_netlink_blackhole_routes() -> Result<(), KillSwitchError> {
    #[cfg(target_os = "linux")]
    {
        // 1. IPv4 0.0.0.0/0 -> RTN_BLACKHOLE in RT_TABLE_MAIN, priority 10
        let v4_msg = build_blackhole_route_msg(false, false, 10);
        send_netlink_route_message(&v4_msg)?;

        // 2. IPv6 ::/0 -> RTN_BLACKHOLE in RT_TABLE_MAIN, priority 10
        let v6_msg = build_blackhole_route_msg(true, false, 10);
        send_netlink_route_message(&v6_msg)?;

        info!("🚨 [LinuxNetlinkIsolator] Installed IPv4 0.0.0.0/0 and IPv6 ::/0 RTN_BLACKHOLE routes.");
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(())
    }
}

/// Removes IPv4 (0.0.0.0/0) and IPv6 (::/0) RTN_BLACKHOLE routes via Netlink NETLINK_ROUTE.
pub fn remove_netlink_blackhole_routes() -> Result<(), KillSwitchError> {
    #[cfg(target_os = "linux")]
    {
        let v4_msg = build_blackhole_route_msg(false, true, 10);
        let _ = send_netlink_route_message(&v4_msg);

        let v6_msg = build_blackhole_route_msg(true, true, 10);
        let _ = send_netlink_route_message(&v6_msg);

        info!("🟢 [LinuxNetlinkIsolator] Removed IPv4 and IPv6 RTN_BLACKHOLE routes.");
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(())
    }
}

/// Linux Native Netlink Isolator implementing `NetworkIsolator`.
pub struct LinuxNetlinkIsolator {
    active: AtomicBool,
}

impl Default for LinuxNetlinkIsolator {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxNetlinkIsolator {
    pub fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
        }
    }

    /// Tests if raw netlink route socket creation succeeds.
    pub fn is_available() -> bool {
        #[cfg(target_os = "linux")]
        {
            unsafe {
                let s = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE);
                if s >= 0 {
                    libc::close(s);
                    true
                } else {
                    false
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

impl NetworkIsolator for LinuxNetlinkIsolator {
    fn engage_quarantine(
        &self,
        preserved_ports: &[u16],
        operator: &str,
        reason: &str,
    ) -> Result<IsolationReceipt, KillSwitchError> {
        let ports = sanitize_firewall_preserved_ports(preserved_ports);

        // Enforce privilege check (only root/CAP_NET_ADMIN or explicit authorized CI self-diagnostic)
        #[cfg(target_os = "linux")]
        {
            let is_root = unsafe { libc::geteuid() == 0 };
            if !is_root && !is_authorized_self_diagnostic() {
                return Err(KillSwitchError::InsufficientPrivileges {
                    details: "Root privileges (or CAP_NET_ADMIN) required to install Linux network quarantine routes and nftables policy".to_string(),
                    remediation: "Restart the application using 'sudo killswitch' or ensure container possesses CAP_NET_ADMIN.".to_string(),
                });
            }

            if is_root {
                install_netlink_blackhole_routes()?;
                install_linux_nftables_quarantine(&ports, &[], &[])?;
            }
        }

        let loopback_ips = vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        ];

        let terminated_count = self.reset_tcp_connections(None).unwrap_or(0);

        self.active.store(true, Ordering::SeqCst);

        let receipt = IsolationReceipt::new(
            "netlink-session-0".to_string(),
            NetworkIsolationEngine::LinuxNetlink,
            Vec::new(),
            Vec::new(),
            vec![
                "netlink_rtn_blackhole_active".to_string(),
                "nftables_inet_killswitch_quarantine".to_string(),
            ],
            ports,
            loopback_ips,
            terminated_count,
            operator.to_string(),
            reason.to_string(),
        );

        tracing::info!(
            "🚨 [LinuxNetlinkIsolator] Quarantined host via Netlink RTN_BLACKHOLE + nftables. Receipt: {}",
            receipt.receipt_id
        );
        Ok(receipt)
    }

    fn restore_quarantine(&self, _receipt: &IsolationReceipt) -> Result<(), KillSwitchError> {
        #[cfg(target_os = "linux")]
        {
            let is_root = unsafe { libc::geteuid() == 0 };
            if !is_root && !is_authorized_self_diagnostic() {
                return Err(KillSwitchError::InsufficientPrivileges {
                    details: "Root privileges (or CAP_NET_ADMIN) required to remove Linux network quarantine".to_string(),
                    remediation: "Restart the application using 'sudo killswitch' or ensure container possesses CAP_NET_ADMIN.".to_string(),
                });
            }
            if is_root {
                let _ = remove_linux_nftables_quarantine();
                let _ = remove_netlink_blackhole_routes();
            }
        }

        self.active.store(false, Ordering::SeqCst);
        tracing::info!(
            "🟢 [LinuxNetlinkIsolator] Restored host network isolation via nftables + Netlink RTM_DELROUTE."
        );
        Ok(())
    }

    fn reset_tcp_connections(
        &self,
        target_ips: Option<&[IpAddr]>,
    ) -> Result<usize, KillSwitchError> {
        #[cfg(target_os = "linux")]
        let closed_count = {
            let mut count = 0usize;
            let is_root = unsafe { libc::geteuid() == 0 };
            if !is_root && !is_authorized_self_diagnostic() {
                return Err(KillSwitchError::InsufficientPrivileges {
                    details: "Root privileges (or CAP_NET_ADMIN) required to destroy kernel sockets via Netlink SOCK_DESTROY".to_string(),
                    remediation: "Restart the application using 'sudo killswitch' or grant CAP_NET_ADMIN.".to_string(),
                });
            }
            if is_root {
                let matches_target = |entry: &LinuxSocketEntry| -> bool {
                    match target_ips {
                        Some(ips) => {
                            ips.contains(&entry.remote_addr) || ips.contains(&entry.local_addr)
                        }
                        None => true,
                    }
                };

                // 1. Destroy non-loopback / alias TCP sockets + blocked loopback proxy sockets
                let mut tcp_targets = get_active_non_loopback_connections().unwrap_or_default();
                for sock in read_and_parse_proc_net_tcp()
                    .into_iter()
                    .flatten()
                    .chain(read_and_parse_proc_net_tcp6().into_iter().flatten())
                {
                    if (QUARANTINE_BLOCKED_LOOPBACK_PROXY_PORTS.contains(&sock.remote_port)
                        || QUARANTINE_BLOCKED_LOOPBACK_PROXY_PORTS.contains(&sock.local_port))
                        && (sock.state == TcpState::Established
                            || sock.state == TcpState::SynSent
                            || sock.state == TcpState::SynRecv
                            || sock.state == TcpState::CloseWait)
                    {
                        tcp_targets.push(sock);
                    }
                }
                for entry in &tcp_targets {
                    if matches_target(entry)
                        && terminate_linux_socket_netlink_proto(entry, 6).is_ok()
                    {
                        count += 1;
                    }
                }

                // 2. Destroy non-loopback UDP (17) & RAW (255) sockets
                if let Ok(udp_raw) = get_active_non_loopback_udp_and_raw_sockets() {
                    for (proto, entry) in &udp_raw {
                        if matches_target(entry)
                            && terminate_linux_socket_netlink_proto(entry, *proto).is_ok()
                        {
                            count += 1;
                        }
                    }
                }
            }
            count
        };
        #[cfg(not(target_os = "linux"))]
        let closed_count = {
            let _ = target_ips;
            let _ = &get_active_non_loopback_connections;
            0usize
        };

        debug!("Linux Netlink reset: severed {} sockets.", closed_count);
        Ok(closed_count)
    }
}

// ---------------------------------------------------------------------------
// 3. /proc/net/tcp & /proc/net/tcp6 Parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Established = 1,
    SynSent = 2,
    SynRecv = 3,
    FinWait1 = 4,
    FinWait2 = 5,
    TimeWait = 6,
    Close = 7,
    CloseWait = 8,
    LastAck = 9,
    Listen = 10,
    Closing = 11,
    Unknown = 0,
}

impl From<u8> for TcpState {
    fn from(val: u8) -> Self {
        match val {
            1 => TcpState::Established,
            2 => TcpState::SynSent,
            3 => TcpState::SynRecv,
            4 => TcpState::FinWait1,
            5 => TcpState::FinWait2,
            6 => TcpState::TimeWait,
            7 => TcpState::Close,
            8 => TcpState::CloseWait,
            9 => TcpState::LastAck,
            10 => TcpState::Listen,
            11 => TcpState::Closing,
            _ => TcpState::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxSocketEntry {
    pub slot: usize,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: IpAddr,
    pub remote_port: u16,
    pub state: TcpState,
    pub inode: u64,
    pub is_ipv6: bool,
}

/// Parses an 8-character little-endian IPv4 hex string from Linux /proc/net tables.
pub fn parse_linux_ipv4_hex(hex_str: &str) -> Option<Ipv4Addr> {
    if hex_str.len() != 8 {
        return None;
    }
    let num = u32::from_str_radix(hex_str, 16).ok()?;
    let octets = [
        (num & 0xFF) as u8,
        ((num >> 8) & 0xFF) as u8,
        ((num >> 16) & 0xFF) as u8,
        ((num >> 24) & 0xFF) as u8,
    ];
    Some(Ipv4Addr::from(octets))
}

/// Parses a 32-character little-endian IPv6 hex string from Linux /proc/net tables.
pub fn parse_linux_ipv6_hex(hex_str: &str) -> Option<Ipv6Addr> {
    if hex_str.len() != 32 {
        return None;
    }
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let chunk = &hex_str[i * 8..(i + 1) * 8];
        let num = u32::from_str_radix(chunk, 16).ok()?;
        octets[i * 4] = (num & 0xFF) as u8;
        octets[i * 4 + 1] = ((num >> 8) & 0xFF) as u8;
        octets[i * 4 + 2] = ((num >> 16) & 0xFF) as u8;
        octets[i * 4 + 3] = ((num >> 24) & 0xFF) as u8;
    }
    Some(Ipv6Addr::from(octets))
}

/// Parses a single line from `/proc/net/tcp` or `/proc/net/tcp6`.
pub fn parse_tcp_line(line: &str, is_v6: bool) -> Result<LinuxSocketEntry, KillSwitchError> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return Err(KillSwitchError::ProcNetTcpParseFailed {
            line: line.to_string(),
        });
    }

    let slot = parts[0].trim_end_matches(':').parse::<usize>().unwrap_or(0);

    // Local address:port
    let (local_ip_hex, local_port_hex) =
        parts[1]
            .split_once(':')
            .ok_or_else(|| KillSwitchError::ProcNetTcpParseFailed {
                line: line.to_string(),
            })?;
    let local_port = u16::from_str_radix(local_port_hex, 16).map_err(|_| {
        KillSwitchError::ProcNetTcpParseFailed {
            line: line.to_string(),
        }
    })?;
    let local_addr = if is_v6 {
        IpAddr::V6(parse_linux_ipv6_hex(local_ip_hex).ok_or_else(|| {
            KillSwitchError::ProcNetTcpParseFailed {
                line: line.to_string(),
            }
        })?)
    } else {
        IpAddr::V4(parse_linux_ipv4_hex(local_ip_hex).ok_or_else(|| {
            KillSwitchError::ProcNetTcpParseFailed {
                line: line.to_string(),
            }
        })?)
    };

    // Remote address:port
    let (remote_ip_hex, remote_port_hex) =
        parts[2]
            .split_once(':')
            .ok_or_else(|| KillSwitchError::ProcNetTcpParseFailed {
                line: line.to_string(),
            })?;
    let remote_port = u16::from_str_radix(remote_port_hex, 16).map_err(|_| {
        KillSwitchError::ProcNetTcpParseFailed {
            line: line.to_string(),
        }
    })?;
    let remote_addr = if is_v6 {
        IpAddr::V6(parse_linux_ipv6_hex(remote_ip_hex).ok_or_else(|| {
            KillSwitchError::ProcNetTcpParseFailed {
                line: line.to_string(),
            }
        })?)
    } else {
        IpAddr::V4(parse_linux_ipv4_hex(remote_ip_hex).ok_or_else(|| {
            KillSwitchError::ProcNetTcpParseFailed {
                line: line.to_string(),
            }
        })?)
    };

    // State
    let state_byte = u8::from_str_radix(parts[3], 16).unwrap_or(0);
    let state = TcpState::from(state_byte);

    // Inode
    let inode = parts[9].parse::<u64>().unwrap_or(0);

    Ok(LinuxSocketEntry {
        slot,
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        state,
        inode,
        is_ipv6: is_v6,
    })
}

/// Parses the full text content of `/proc/net/tcp` or `/proc/net/tcp6`.
pub fn parse_proc_net_content(content: &str, is_v6: bool) -> Vec<LinuxSocketEntry> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| parse_tcp_line(line, is_v6).ok())
        .collect()
}

fn read_and_parse_proc_net_file(
    path: &str,
    is_v6: bool,
) -> Result<Vec<LinuxSocketEntry>, KillSwitchError> {
    let content =
        std::fs::read_to_string(path).map_err(|_| KillSwitchError::ProcNetTcpParseFailed {
            line: format!("Could not open {path}"),
        })?;
    Ok(parse_proc_net_content(&content, is_v6))
}

#[inline]
fn is_exact_localhost_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4 == Ipv4Addr::LOCALHOST,
        IpAddr::V6(v6) => {
            v6 == Ipv6Addr::LOCALHOST || v6.to_ipv4_mapped() == Some(Ipv4Addr::LOCALHOST)
        }
    }
}

#[inline]
fn is_unspecified_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_unspecified() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_unspecified())
        }
    }
}

/// Reads and parses live `/proc/net/tcp` (IPv4).
pub fn read_and_parse_proc_net_tcp() -> Result<Vec<LinuxSocketEntry>, KillSwitchError> {
    read_and_parse_proc_net_file("/proc/net/tcp", false)
}

/// Reads and parses live `/proc/net/tcp6` (IPv6).
pub fn read_and_parse_proc_net_tcp6() -> Result<Vec<LinuxSocketEntry>, KillSwitchError> {
    read_and_parse_proc_net_file("/proc/net/tcp6", true)
}

/// Reads and parses live `/proc/net/udp` (IPv4).
pub fn read_and_parse_proc_net_udp() -> Result<Vec<LinuxSocketEntry>, KillSwitchError> {
    read_and_parse_proc_net_file("/proc/net/udp", false)
}

/// Reads and parses live `/proc/net/udp6` (IPv6).
pub fn read_and_parse_proc_net_udp6() -> Result<Vec<LinuxSocketEntry>, KillSwitchError> {
    read_and_parse_proc_net_file("/proc/net/udp6", true)
}

/// Reads and parses live `/proc/net/raw` (IPv4).
pub fn read_and_parse_proc_net_raw() -> Result<Vec<LinuxSocketEntry>, KillSwitchError> {
    read_and_parse_proc_net_file("/proc/net/raw", false)
}

/// Reads and parses live `/proc/net/raw6` (IPv6).
pub fn read_and_parse_proc_net_raw6() -> Result<Vec<LinuxSocketEntry>, KillSwitchError> {
    read_and_parse_proc_net_file("/proc/net/raw6", true)
}

/// Enumerates all active non-localhost TCP connections (including `127.0.0.2+` loopback aliases
/// and external connections targeting port 3030).
pub fn get_active_non_loopback_connections() -> Result<Vec<LinuxSocketEntry>, KillSwitchError> {
    let mut entries = Vec::new();
    if let Ok(v4) = read_and_parse_proc_net_tcp() {
        entries.extend(v4);
    }
    if let Ok(v6) = read_and_parse_proc_net_tcp6() {
        entries.extend(v6);
    }

    let non_loopback: Vec<LinuxSocketEntry> = entries
        .into_iter()
        .filter(|e| {
            !is_exact_localhost_ip(e.remote_addr)
                && !is_unspecified_ip(e.remote_addr)
                && (e.state == TcpState::Established
                    || e.state == TcpState::SynSent
                    || e.state == TcpState::SynRecv
                    || e.state == TcpState::CloseWait)
        })
        .collect();

    Ok(non_loopback)
}

/// Enumerates active non-localhost UDP (`17`) and RAW (`255`) sockets for `SOCK_DESTROY` / audit.
pub fn get_active_non_loopback_udp_and_raw_sockets(
) -> Result<Vec<(u8, LinuxSocketEntry)>, KillSwitchError> {
    let mut out = Vec::new();
    for entry in read_and_parse_proc_net_udp()
        .into_iter()
        .flatten()
        .chain(read_and_parse_proc_net_udp6().into_iter().flatten())
    {
        if !is_exact_localhost_ip(entry.local_addr)
            || (!is_unspecified_ip(entry.remote_addr) && !is_exact_localhost_ip(entry.remote_addr))
        {
            out.push((17u8, entry));
        }
    }
    for entry in read_and_parse_proc_net_raw()
        .into_iter()
        .flatten()
        .chain(read_and_parse_proc_net_raw6().into_iter().flatten())
    {
        if !is_exact_localhost_ip(entry.local_addr)
            || (!is_unspecified_ip(entry.remote_addr) && !is_exact_localhost_ip(entry.remote_addr))
        {
            out.push((255u8, entry));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PROC_NET_TCP: &str = r#"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0BD6 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 35123 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0016 0200007F:C001 01 00000000:00000000 00:00000000 00000000  1000        0 35124 1 0000000000000000 100 0 0 10 0
   2: 0501A8C0:D431 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 35125 1 0000000000000000 100 0 0 10 0
"#;

    const SAMPLE_PROC_NET_TCP6: &str = r#"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:0BD6 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 45001 1 0000000000000000 100 0 0 10 0
"#;

    #[test]
    fn test_parse_linux_ipv4_hex() {
        // 0100007F -> 127.0.0.1
        let ip = parse_linux_ipv4_hex("0100007F").unwrap();
        assert_eq!(ip, Ipv4Addr::new(127, 0, 0, 1));

        // 08080808 -> 8.8.8.8
        let ip_dns = parse_linux_ipv4_hex("08080808").unwrap();
        assert_eq!(ip_dns, Ipv4Addr::new(8, 8, 8, 8));

        // 0501A8C0 -> 192.168.1.5
        let ip_lan = parse_linux_ipv4_hex("0501A8C0").unwrap();
        assert_eq!(ip_lan, Ipv4Addr::new(192, 168, 1, 5));
    }

    #[test]
    fn test_parse_linux_ipv6_hex() {
        // 00000000000000000000000001000000 -> ::1
        let ip = parse_linux_ipv6_hex("00000000000000000000000001000000").unwrap();
        assert_eq!(ip, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    }

    #[test]
    fn test_parse_proc_net_content() {
        let entries = parse_proc_net_content(SAMPLE_PROC_NET_TCP, false);
        assert_eq!(entries.len(), 3);

        // Entry 0: 127.0.0.1:3030 Listen
        assert_eq!(
            entries[0].local_addr,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(entries[0].local_port, 3030);
        assert_eq!(entries[0].state, TcpState::Listen);

        // Entry 2: 192.168.1.5:54321 -> 8.8.8.8:53 Established
        assert_eq!(
            entries[2].remote_addr,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
        );
        assert_eq!(entries[2].remote_port, 53);
        assert_eq!(entries[2].state, TcpState::Established);

        // IPv6 test
        let entries_v6 = parse_proc_net_content(SAMPLE_PROC_NET_TCP6, true);
        assert_eq!(entries_v6.len(), 1);
        assert_eq!(
            entries_v6[0].local_addr,
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))
        );
        assert_eq!(entries_v6[0].local_port, 3030);
    }

    #[test]
    fn test_linux_netlink_isolator_engagement() {
        let isolator = LinuxNetlinkIsolator::new();
        let res = isolator.engage_quarantine(&[3030, 53, 8080, 445], "admin", "test isolation");
        #[cfg(target_os = "linux")]
        {
            let is_root = unsafe { libc::geteuid() == 0 };
            if !is_root && !is_authorized_self_diagnostic() {
                assert!(matches!(
                    res,
                    Err(KillSwitchError::InsufficientPrivileges { .. })
                ));
                return;
            }
        }
        assert!(res.is_ok(), "engage_quarantine failed: {:?}", res);
        let receipt = res.unwrap();
        assert_eq!(receipt.engine, NetworkIsolationEngine::LinuxNetlink);
        assert_eq!(receipt.preserved_ports, vec![3030]);
        assert_eq!(
            receipt.netlink_rule_ids,
            vec![
                "netlink_rtn_blackhole_active".to_string(),
                "nftables_inet_killswitch_quarantine".to_string(),
            ]
        );
        assert!(isolator.restore_quarantine(&receipt).is_ok());

        // Verify Landlock default sandbox config strictly excludes port 53
        let landlock_cfg = LandlockSandboxConfig::default();
        assert_eq!(landlock_cfg.allowed_tcp_ports, vec![3030]);
    }

    #[test]
    fn test_linux_nftables_quarantine_script_hardening() {
        let script = generate_linux_nftables_quarantine_script(
            &[3030, 53, 8080, 445, 9050, 3456],
            &["killswitch.slice/ks-agent-1.scope"],
            &[1001],
        );
        assert!(script.contains("policy drop;"));
        assert!(!script.contains("iif lo accept"));
        assert!(!script.contains("oif lo accept"));
        assert!(script.contains("ip saddr != 127.0.0.1 ip daddr 127.0.0.0/8 drop"));
        assert!(script.contains("ip daddr 169.254.0.0/16 drop"));
        assert!(script.contains("ip6 daddr fe80::/10 drop"));
        assert!(script.contains("udp dport { 53, 67, 68, 546, 547, 853, 443 } drop"));
        assert!(script.contains("tcp dport { 1080, 3128, 8080, 8888, 9050 } drop"));
        assert!(script.contains("tcp dport { 135, 445, 5985, 5986 } drop"));
        assert!(
            script.contains("socket cgroupv2 level 1 \"killswitch.slice/ks-agent-1.scope\" drop")
        );
        assert!(script.contains("meta skuid 1001 drop"));
        assert!(script.contains("ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp dport 3030 accept"));
        assert!(script.contains("ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp dport 3456 accept"));
        assert!(!script.contains("tcp dport 8080 accept"));
        assert!(!script.contains("tcp dport 53 accept"));
    }

    #[test]
    fn test_agent_seccomp_bpf_filter_layout() {
        let no_net = build_agent_seccomp_bpf(false);
        assert!(!no_net.is_empty());
        assert_eq!(no_net[0].code, BPF_LD_W_ABS);
        assert_eq!(no_net[0].k, 4, "Must validate seccomp_data.arch first");
        assert_eq!(no_net[2].k, SECCOMP_RET_KILL_PROCESS);
        assert!(no_net.iter().any(|ins| ins.k == SECCOMP_RET_ERRNO_EPERM));
        assert!(no_net.iter().any(|ins| ins.k == SECCOMP_RET_ALLOW));

        let with_net = build_agent_seccomp_bpf(true);
        assert!(
            no_net.len() > with_net.len(),
            "network-off BPF adds AF_UNIX-only check"
        );
    }

    #[test]
    fn test_netlink_blackhole_route_binary_layout() {
        // Test IPv4 blackhole route message
        let v4_msg = build_blackhole_route_msg(false, false, 10);
        assert_eq!(v4_msg.len(), 36);
        let hdr = unsafe { &*(v4_msg.as_ptr() as *const NlMsgHdr) };
        assert_eq!(hdr.nlmsg_len, 36);
        assert_eq!(hdr.nlmsg_type, RTM_NEWROUTE);
        assert_eq!(
            hdr.nlmsg_flags,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE
        );

        let rt = unsafe { &*(v4_msg.as_ptr().add(16) as *const RtMsg) };
        assert_eq!(rt.rtm_dst_len, 0, "Default route must have dst_len = 0");
        assert_eq!(rt.rtm_table, RT_TABLE_MAIN);
        assert_eq!(rt.rtm_type, RTN_BLACKHOLE);
        assert_eq!(rt.rtm_protocol, RTPROT_STATIC);

        // Test IPv6 blackhole route message
        let v6_msg = build_blackhole_route_msg(true, false, 10);
        assert_eq!(v6_msg.len(), 36);
        let rt6 = unsafe { &*(v6_msg.as_ptr().add(16) as *const RtMsg) };
        assert_eq!(rt6.rtm_dst_len, 0);
        assert_eq!(rt6.rtm_type, RTN_BLACKHOLE);

        // Test RTM_DELROUTE message
        let del_msg = build_blackhole_route_msg(false, true, 10);
        let hdr_del = unsafe { &*(del_msg.as_ptr() as *const NlMsgHdr) };
        assert_eq!(hdr_del.nlmsg_type, RTM_DELROUTE);
        assert_eq!(hdr_del.nlmsg_flags, NLM_F_REQUEST | NLM_F_ACK);
    }

    #[test]
    fn test_netlink_sock_destroy_binary_layout_and_udp_proto() {
        let entry = LinuxSocketEntry {
            slot: 1,
            local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
            local_port: 54321,
            remote_addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            remote_port: 53,
            state: TcpState::Established,
            inode: 12345,
            is_ipv6: false,
        };

        let msg = build_sock_destroy_msg(&entry);
        assert_eq!(msg.len(), 72);
        let hdr = unsafe { &*(msg.as_ptr() as *const NlMsgHdr) };
        assert_eq!(hdr.nlmsg_len, 72);
        assert_eq!(hdr.nlmsg_type, SOCK_DESTROY);

        let req = unsafe { &*(msg.as_ptr().add(16) as *const InetDiagReqV2) };
        assert_eq!(req.sdiag_protocol, 6, "Must target IPPROTO_TCP");
        assert_eq!(req.id.idiag_sport, 54321u16.to_be());
        assert_eq!(req.id.idiag_dport, 53u16.to_be());
        assert_eq!(req.id.idiag_cookie, [0xFFFFFFFF, 0xFFFFFFFF]);

        let udp_msg = build_sock_destroy_msg_for_proto(&entry, 17);
        let udp_req = unsafe { &*(udp_msg.as_ptr().add(16) as *const InetDiagReqV2) };
        assert_eq!(udp_req.sdiag_protocol, 17, "Must target IPPROTO_UDP");
    }

    #[test]
    fn test_exact_localhost_and_unspecified_ip_helpers() {
        assert!(is_exact_localhost_ip(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        ))));
        assert!(!is_exact_localhost_ip(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 2
        ))));
        assert!(is_exact_localhost_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_unspecified_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(is_unspecified_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }
}
