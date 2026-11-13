//! Kernel TCP socket table peer PID resolution.
//!
//! Resolves the actual OS process ID owning a local TCP loopback client socket
//! directly from the operating system's kernel TCP connection table:
//! - Windows: `GetExtendedTcpTable` (`TCP_TABLE_OWNER_PID_ALL`) via `iphlpapi.dll`
//! - Linux: `/proc/net/tcp` & `/proc/net/tcp6` inode correlation to `/proc/<pid>/fd/`
//! - macOS / Unix fallback: native OS process identity
//!
//! This prevents caller process anti-hijacking bypasses where an attacker or rogue
//! quarantined process supplies a false `caller_pid` in request JSON.

use killswitch_types::errors::KillSwitchError;
use std::net::SocketAddr;

/// Resolves the actual OS process ID owning a local loopback TCP client socket.
#[cfg(windows)]
pub fn resolve_loopback_peer_pid(
    peer_addr: SocketAddr,
    bound_port: u16,
) -> Result<u32, KillSwitchError> {
    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const TCP_TABLE_OWNER_PID_ALL: i32 = 5;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MibTcpRowOwnerPid {
        dw_state: u32,
        dw_local_addr: u32,
        dw_local_port: u32,
        dw_remote_addr: u32,
        dw_remote_port: u32,
        dw_owning_pid: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MibTcp6RowOwnerPid {
        uc_local_addr: [u8; 16],
        dw_local_scope_id: u32,
        dw_local_port: u32,
        uc_remote_addr: [u8; 16],
        dw_remote_scope_id: u32,
        dw_remote_port: u32,
        dw_state: u32,
        dw_owning_pid: u32,
    }

    #[link(name = "iphlpapi")]
    extern "system" {
        fn GetExtendedTcpTable(
            p_tcp_table: *mut u8,
            pdw_size: *mut u32,
            b_order: i32,
            ul_af: u32,
            table_class: i32,
            reserved: u32,
        ) -> u32;
    }

    let normalized_peer_addr = match peer_addr {
        SocketAddr::V6(ref v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::new(std::net::IpAddr::V4(v4), v6.port())
            } else {
                match v6.ip().to_canonical() {
                    std::net::IpAddr::V4(v4) => {
                        SocketAddr::new(std::net::IpAddr::V4(v4), v6.port())
                    }
                    std::net::IpAddr::V6(_) => peer_addr,
                }
            }
        }
        SocketAddr::V4(_) => peer_addr,
    };

    let peer_port = normalized_peer_addr.port();

    match normalized_peer_addr {
        SocketAddr::V4(_) => {
            unsafe {
                let mut retries = 0;
                let mut buf;
                loop {
                    let mut size: u32 = 0;
                    let res = GetExtendedTcpTable(
                        std::ptr::null_mut(),
                        &mut size,
                        0,
                        AF_INET,
                        TCP_TABLE_OWNER_PID_ALL,
                        0,
                    );
                    if (res != 0 && res != ERROR_INSUFFICIENT_BUFFER) || size == 0 {
                        return Err(KillSwitchError::NativeOsError(
                            "Failed to query GetExtendedTcpTable size for IPv4".to_string(),
                        ));
                    }
                    let alloc_size = (size as usize).saturating_add(4096);
                    let mut curr_size: u32 = alloc_size as u32;
                    buf = vec![0u8; alloc_size];
                    let ret = GetExtendedTcpTable(
                        buf.as_mut_ptr(),
                        &mut curr_size,
                        0,
                        AF_INET,
                        TCP_TABLE_OWNER_PID_ALL,
                        0,
                    );
                    if ret == 0 {
                        break;
                    } else if ret == ERROR_INSUFFICIENT_BUFFER && retries < 3 {
                        retries += 1;
                        continue;
                    } else {
                        return Err(KillSwitchError::NativeOsError(format!(
                            "Failed to read GetExtendedTcpTable for IPv4 (code {})",
                            ret
                        )));
                    }
                }
                let num_entries = std::ptr::read_unaligned(buf.as_ptr() as *const u32) as usize;
                let rows_ptr = buf.as_ptr().add(4) as *const MibTcpRowOwnerPid;
                let max_rows =
                    (buf.len().saturating_sub(4)) / std::mem::size_of::<MibTcpRowOwnerPid>();
                let count = num_entries.min(max_rows);

                for i in 0..count {
                    let row = std::ptr::read_unaligned(rows_ptr.add(i));
                    let lport = u16::from_be((row.dw_local_port & 0xFFFF) as u16);
                    let rport = u16::from_be((row.dw_remote_port & 0xFFFF) as u16);
                    // Match peer port to the client's local port and bound port to remote port
                    if lport == peer_port && (rport == bound_port || bound_port == 0) {
                        if row.dw_owning_pid == 0 {
                            return Err(KillSwitchError::NativeOsError(format!(
                                "Socket matching peer port {} -> server port {} is closed/unowned (PID 0)",
                                peer_port, bound_port
                            )));
                        }
                        return Ok(row.dw_owning_pid);
                    }
                }
            }
        }
        SocketAddr::V6(_) => unsafe {
            let mut retries = 0;
            let mut buf;
            loop {
                let mut size: u32 = 0;
                let res = GetExtendedTcpTable(
                    std::ptr::null_mut(),
                    &mut size,
                    0,
                    AF_INET6,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );
                if (res != 0 && res != ERROR_INSUFFICIENT_BUFFER) || size == 0 {
                    return Err(KillSwitchError::NativeOsError(
                        "Failed to query GetExtendedTcpTable size for IPv6".to_string(),
                    ));
                }
                let alloc_size = (size as usize).saturating_add(4096);
                let mut curr_size: u32 = alloc_size as u32;
                buf = vec![0u8; alloc_size];
                let ret = GetExtendedTcpTable(
                    buf.as_mut_ptr(),
                    &mut curr_size,
                    0,
                    AF_INET6,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                );
                if ret == 0 {
                    break;
                } else if ret == ERROR_INSUFFICIENT_BUFFER && retries < 3 {
                    retries += 1;
                    continue;
                } else {
                    return Err(KillSwitchError::NativeOsError(format!(
                        "Failed to read GetExtendedTcpTable for IPv6 (code {})",
                        ret
                    )));
                }
            }
            let num_entries = std::ptr::read_unaligned(buf.as_ptr() as *const u32) as usize;
            let rows_ptr = buf.as_ptr().add(4) as *const MibTcp6RowOwnerPid;
            let max_rows =
                (buf.len().saturating_sub(4)) / std::mem::size_of::<MibTcp6RowOwnerPid>();
            let count = num_entries.min(max_rows);

            for i in 0..count {
                let row = std::ptr::read_unaligned(rows_ptr.add(i));
                let lport = u16::from_be((row.dw_local_port & 0xFFFF) as u16);
                let rport = u16::from_be((row.dw_remote_port & 0xFFFF) as u16);
                if lport == peer_port && (rport == bound_port || bound_port == 0) {
                    if row.dw_owning_pid == 0 {
                        return Err(KillSwitchError::NativeOsError(format!(
                                "Socket matching peer port {} -> server port {} is closed/unowned (PID 0)",
                                peer_port, bound_port
                            )));
                    }
                    return Ok(row.dw_owning_pid);
                }
            }
        },
    }

    Err(KillSwitchError::NativeOsError(format!(
        "No kernel TCP table entry found matching peer port {} -> server port {}",
        peer_port, bound_port
    )))
}

#[cfg(target_os = "linux")]
pub fn resolve_loopback_peer_pid(
    peer_addr: SocketAddr,
    bound_port: u16,
) -> Result<u32, KillSwitchError> {
    let normalized_peer_addr = match peer_addr {
        SocketAddr::V6(ref v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::new(std::net::IpAddr::V4(v4), v6.port())
            } else {
                match v6.ip().to_canonical() {
                    std::net::IpAddr::V4(v4) => {
                        SocketAddr::new(std::net::IpAddr::V4(v4), v6.port())
                    }
                    std::net::IpAddr::V6(_) => peer_addr,
                }
            }
        }
        SocketAddr::V4(_) => peer_addr,
    };
    let peer_port = normalized_peer_addr.port();

    let entries = match normalized_peer_addr {
        SocketAddr::V4(_) => crate::landlock::read_and_parse_proc_net_tcp()?,
        SocketAddr::V6(_) => crate::landlock::read_and_parse_proc_net_tcp6()?,
    };

    for entry in entries {
        if entry.local_port == peer_port && (entry.remote_port == bound_port || bound_port == 0) {
            let target = format!("socket:[{}]", entry.inode);
            if let Ok(proc_dir) = std::fs::read_dir("/proc") {
                for p_entry in proc_dir.flatten() {
                    if let Ok(pid) = p_entry.file_name().to_string_lossy().parse::<u32>() {
                        let fd_dir_path = p_entry.path().join("fd");
                        if let Ok(fd_dir) = std::fs::read_dir(fd_dir_path) {
                            for fd_entry in fd_dir.flatten() {
                                if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                                    if link.to_string_lossy() == target {
                                        return Ok(pid);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Err(KillSwitchError::NativeOsError(format!(
        "No matching Linux socket inode found for peer port {} -> server port {}",
        peer_port, bound_port
    )))
}

#[cfg(target_os = "macos")]
pub fn resolve_loopback_peer_pid(
    peer_addr: SocketAddr,
    bound_port: u16,
) -> Result<u32, KillSwitchError> {
    if !peer_addr.ip().is_loopback() {
        return Err(KillSwitchError::NativeOsError(format!(
            "Non-loopback peer IP {} rejected during peer PID resolution",
            peer_addr.ip()
        )));
    }

    let peer_port = peer_addr.port();
    const PROC_ALL_PIDS: u32 = 1;
    const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
    const SOCKINFO_IN: i32 = 1;
    const SOCKINFO_TCP: i32 = 2;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct DarwinProcFileInfo {
        fi_openflags: u32,
        fi_status: u32,
        fi_offset: i64,
        fi_type: i32,
        fi_guardflags: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct DarwinVinfoStat {
        vst_dev: u32,
        vst_mode: u16,
        vst_nlink: u16,
        vst_ino: u64,
        vst_uid: u32,
        vst_gid: u32,
        vst_atime: i64,
        vst_atimensec: i64,
        vst_mtime: i64,
        vst_mtimensec: i64,
        vst_ctime: i64,
        vst_ctimensec: i64,
        vst_birthtime: i64,
        vst_birthtimensec: i64,
        vst_size: i64,
        vst_blocks: i64,
        vst_blksize: i32,
        vst_flags: u32,
        vst_gen: u32,
        vst_rdev: u32,
        vst_qspare: [i64; 2],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct DarwinSockbufInfo {
        sbi_cc: u32,
        sbi_hiwat: u32,
        sbi_mbcnt: u32,
        sbi_mbmax: u32,
        sbi_lowat: u32,
        sbi_flags: i16,
        sbi_timeo: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct DarwinSocketInfoHeader {
        soi_stat: DarwinVinfoStat,
        soi_so: u64,
        soi_pcb: u64,
        soi_type: i32,
        soi_protocol: i32,
        soi_family: i32,
        soi_options: i16,
        soi_linger: i16,
        soi_state: i16,
        soi_qlen: i16,
        soi_incqlen: i16,
        soi_qlimit: i16,
        soi_timeo: i16,
        soi_error: u16,
        soi_oobmark: u32,
        soi_rcv: DarwinSockbufInfo,
        soi_snd: DarwinSockbufInfo,
        soi_kind: i32,
        rfu_1: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct DarwinInSockInfoPrefix {
        insi_fport: i32,
        insi_lport: i32,
    }

    #[repr(C, align(8))]
    struct DarwinSocketFdInfoBuf {
        pfi: DarwinProcFileInfo,
        psi_header: DarwinSocketInfoHeader,
        insi: DarwinInSockInfoPrefix,
        _tail: [u8; 752],
    }

    unsafe {
        let estimated_bytes = libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0);
        if estimated_bytes <= 0 {
            return Err(KillSwitchError::NativeOsError(
                "macOS proc_listpids returned empty/error PID count".to_string(),
            ));
        }

        let pid_cap = ((estimated_bytes as usize) / std::mem::size_of::<libc::pid_t>()) + 128;
        let mut pids: Vec<libc::pid_t> = vec![0; pid_cap];
        let filled_bytes = libc::proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr() as *mut libc::c_void,
            (pids.len() * std::mem::size_of::<libc::pid_t>()) as libc::c_int,
        );
        if filled_bytes <= 0 {
            return Err(KillSwitchError::NativeOsError(
                "macOS proc_listpids failed reading active PIDs".to_string(),
            ));
        }
        let pid_count = (filled_bytes as usize) / std::mem::size_of::<libc::pid_t>();

        for &pid in &pids[..pid_count] {
            if pid <= 0 {
                continue;
            }
            let fd_bytes = libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                std::ptr::null_mut(),
                0,
            );
            if fd_bytes <= 0 {
                continue;
            }
            let fd_cap = ((fd_bytes as usize) / std::mem::size_of::<libc::proc_fdinfo>()) + 16;
            let mut fds: Vec<libc::proc_fdinfo> = vec![std::mem::zeroed(); fd_cap];
            let actual_fd_bytes = libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                fds.as_mut_ptr() as *mut libc::c_void,
                (fds.len() * std::mem::size_of::<libc::proc_fdinfo>()) as libc::c_int,
            );
            if actual_fd_bytes <= 0 {
                continue;
            }
            let fd_count = (actual_fd_bytes as usize) / std::mem::size_of::<libc::proc_fdinfo>();

            for fd_entry in &fds[..fd_count] {
                if fd_entry.proc_fdtype as libc::c_int != libc::PROX_FDTYPE_SOCKET {
                    continue;
                }
                let mut sock_buf: DarwinSocketFdInfoBuf = std::mem::zeroed();
                let res = libc::proc_pidfdinfo(
                    pid,
                    fd_entry.proc_fd,
                    PROC_PIDFDSOCKETINFO,
                    (&mut sock_buf as *mut DarwinSocketFdInfoBuf) as *mut libc::c_void,
                    std::mem::size_of::<DarwinSocketFdInfoBuf>() as libc::c_int,
                );
                if res <= 0 {
                    continue;
                }
                let fam = sock_buf.psi_header.soi_family;
                let proto = sock_buf.psi_header.soi_protocol;
                let kind = sock_buf.psi_header.soi_kind;
                if (fam == libc::AF_INET || fam == libc::AF_INET6)
                    && (proto == libc::IPPROTO_TCP || kind == SOCKINFO_TCP)
                    && (kind == SOCKINFO_IN || kind == SOCKINFO_TCP)
                {
                    let lport = u16::from_be((sock_buf.insi.insi_lport & 0xFFFF) as u16);
                    let rport = u16::from_be((sock_buf.insi.insi_fport & 0xFFFF) as u16);
                    if lport == peer_port && (rport == bound_port || bound_port == 0) {
                        return Ok(pid as u32);
                    }
                }
            }
        }
    }

    Err(KillSwitchError::NativeOsError(format!(
        "No matching macOS socket found via proc_pidinfo for peer port {} -> server port {}",
        peer_port, bound_port
    )))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn resolve_loopback_peer_pid(
    _peer_addr: SocketAddr,
    _bound_port: u16,
) -> Result<u32, KillSwitchError> {
    Err(KillSwitchError::NativeOsError(
        "Loopback peer PID resolution is not supported on this platform (fail-closed)".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::net::TcpStream;

    #[test]
    fn test_resolve_loopback_peer_pid_self() {
        // Bind an ephemeral listener on 127.0.0.1
        let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind ephemeral listener");
        let server_port = listener.local_addr().unwrap().port();

        // Connect from current process
        let client = TcpStream::connect(format!("127.0.0.1:{}", server_port))
            .expect("Must connect to ephemeral listener");
        let client_local_addr = client.local_addr().expect("Must have local addr");

        // Accept connection to establish socket in TCP table
        let (server_stream, _peer_addr) = listener.accept().expect("Must accept connection");

        // Now resolve peer PID from the client's local address
        let resolved_pid = resolve_loopback_peer_pid(client_local_addr, server_port);
        #[cfg(any(windows, target_os = "linux", target_os = "macos"))]
        {
            assert!(
                resolved_pid.is_ok(),
                "Failed to resolve PID: {:?}",
                resolved_pid
            );
            let pid = resolved_pid.unwrap();
            assert_eq!(
                pid,
                std::process::id(),
                "Resolved PID should match current test runner process"
            );
        }
        #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
        {
            assert!(
                matches!(
                    resolved_pid,
                    Err(KillSwitchError::NativeOsError(ref msg)) if msg.contains("not supported on this platform")
                ),
                "Expected unsupported platform fail-closed error, got: {:?}",
                resolved_pid
            );
        }

        drop(client);
        drop(server_stream);
    }
}
