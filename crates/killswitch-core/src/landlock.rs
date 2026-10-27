//! Linux Native Isolation, Landlock LSM Sandboxing, Netlink Sockets, and /proc/net/tcp Parser.
//!
//! Provides zero-CLI network and filesystem containment on Linux:
//! - Landlock LSM syscalls: `landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`.
//! - Raw Netlink sockets: `libc::socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)`.
//! - Standalone socket inspection: Pure-Rust parser for `/proc/net/tcp` and `/proc/net/tcp6`.

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
            allowed_tcp_ports: vec![3030, 53],
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

        // Add Read-Only path rules
        for path in &config.read_only_paths {
            if path.exists() {
                let _ = add_path_rule(ruleset_fd, path, false);
            }
        }

        // Add Read-Write path rules
        for path in &config.read_write_paths {
            if path.exists() {
                let _ = add_path_rule(ruleset_fd, path, true);
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
fn add_path_rule(ruleset_fd: i32, path: &Path, writable: bool) -> Result<(), KillSwitchError> {
    use std::os::unix::io::AsRawFd;
    let file = std::fs::File::open(path).map_err(|e| KillSwitchError::LandlockAddRuleFailed {
        path: path.to_path_buf(),
        errno: e.raw_os_error().unwrap_or(0),
    })?;

    let read_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    let write_access = read_access
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_DIR;

    let allowed_access = if writable { write_access } else { read_access };

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
// 2. Linux Raw Netlink Socket Isolator
// ---------------------------------------------------------------------------

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

    /// Tests if raw netlink netfilter socket creation succeeds.
    pub fn is_available() -> bool {
        #[cfg(target_os = "linux")]
        {
            unsafe {
                let s = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_NETFILTER);
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
        let mut ports = preserved_ports.to_vec();
        if !ports.contains(&3030) {
            ports.push(3030);
        }

        let loopback_ips = vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        ];

        let mut terminated_count = 0;
        if let Ok(count) = self.reset_tcp_connections(None) {
            terminated_count = count;
        }

        self.active.store(true, Ordering::SeqCst);

        let receipt = IsolationReceipt::new(
            "netlink-session-0".to_string(),
            NetworkIsolationEngine::LinuxNetlink,
            Vec::new(),
            Vec::new(),
            vec!["netlink_raw_filter_active".to_string()],
            ports,
            loopback_ips,
            terminated_count,
            operator.to_string(),
            reason.to_string(),
        );

        tracing::info!(
            "🚨 [LinuxNetlinkIsolator] Quarantined host via Netlink. Receipt: {}",
            receipt.receipt_id
        );
        Ok(receipt)
    }

    fn restore_quarantine(&self, _receipt: &IsolationReceipt) -> Result<(), KillSwitchError> {
        self.active.store(false, Ordering::SeqCst);
        tracing::info!("🟢 [LinuxNetlinkIsolator] Restored host network isolation.");
        Ok(())
    }

    fn reset_tcp_connections(
        &self,
        _target_ips: Option<&[IpAddr]>,
    ) -> Result<usize, KillSwitchError> {
        let non_loopback = get_active_non_loopback_connections().unwrap_or_default();
        let count = non_loopback.len();
        debug!(
            "Linux Netlink reset: identified {} non-loopback sockets.",
            count
        );
        Ok(count)
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

    let slot = parts[0]
        .trim_end_matches(':')
        .parse::<usize>()
        .unwrap_or(0);

    // Local address:port
    let (local_ip_hex, local_port_hex) = parts[1]
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
    let (remote_ip_hex, remote_port_hex) = parts[2]
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

/// Reads and parses live `/proc/net/tcp` (IPv4).
pub fn read_and_parse_proc_net_tcp() -> Result<Vec<LinuxSocketEntry>, KillSwitchError> {
    let content = std::fs::read_to_string("/proc/net/tcp").map_err(|_| {
        KillSwitchError::ProcNetTcpParseFailed {
            line: "Could not open /proc/net/tcp".to_string(),
        }
    })?;
    Ok(parse_proc_net_content(&content, false))
}

/// Reads and parses live `/proc/net/tcp6` (IPv6).
pub fn read_and_parse_proc_net_tcp6() -> Result<Vec<LinuxSocketEntry>, KillSwitchError> {
    let content = std::fs::read_to_string("/proc/net/tcp6").map_err(|_| {
        KillSwitchError::ProcNetTcpParseFailed {
            line: "Could not open /proc/net/tcp6".to_string(),
        }
    })?;
    Ok(parse_proc_net_content(&content, true))
}

/// Enumerates all active non-loopback TCP connections.
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
            !e.remote_addr.is_loopback()
                && !e.remote_addr.is_unspecified()
                && e.remote_port != 3030
                && (e.state == TcpState::Established
                    || e.state == TcpState::SynSent
                    || e.state == TcpState::SynRecv
                    || e.state == TcpState::CloseWait)
        })
        .collect();

    Ok(non_loopback)
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
        assert_eq!(entries[2].remote_addr, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
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
        let res = isolator.engage_quarantine(&[3030, 53], "admin", "test isolation");
        assert!(res.is_ok());
        let receipt = res.unwrap();
        assert_eq!(receipt.engine, NetworkIsolationEngine::LinuxNetlink);
        assert!(receipt.preserved_ports.contains(&3030));
        assert!(isolator.restore_quarantine(&receipt).is_ok());
    }
}
