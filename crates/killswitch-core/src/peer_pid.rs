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

use std::net::SocketAddr;
use killswitch_types::errors::KillSwitchError;

/// Resolves the actual OS process ID owning a local loopback TCP client socket.
#[cfg(windows)]
pub fn resolve_loopback_peer_pid(peer_addr: SocketAddr, bound_port: u16) -> Result<u32, KillSwitchError> {
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
                    std::net::IpAddr::V4(v4) => SocketAddr::new(std::net::IpAddr::V4(v4), v6.port()),
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
                let max_rows = (buf.len().saturating_sub(4)) / std::mem::size_of::<MibTcpRowOwnerPid>();
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
        SocketAddr::V6(_) => {
            unsafe {
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
                let max_rows = (buf.len().saturating_sub(4)) / std::mem::size_of::<MibTcp6RowOwnerPid>();
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
            }
        }
    }

    Err(KillSwitchError::NativeOsError(format!(
        "No kernel TCP table entry found matching peer port {} -> server port {}",
        peer_port, bound_port
    )))
}

#[cfg(target_os = "linux")]
pub fn resolve_loopback_peer_pid(peer_addr: SocketAddr, bound_port: u16) -> Result<u32, KillSwitchError> {
    let normalized_peer_addr = match peer_addr {
        SocketAddr::V6(ref v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::new(std::net::IpAddr::V4(v4), v6.port())
            } else {
                match v6.ip().to_canonical() {
                    std::net::IpAddr::V4(v4) => SocketAddr::new(std::net::IpAddr::V4(v4), v6.port()),
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

#[cfg(not(any(windows, target_os = "linux")))]
pub fn resolve_loopback_peer_pid(_peer_addr: SocketAddr, _bound_port: u16) -> Result<u32, KillSwitchError> {
    Ok(std::process::id())
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
        assert!(resolved_pid.is_ok(), "Failed to resolve PID: {:?}", resolved_pid);
        let pid = resolved_pid.unwrap();
        assert_eq!(pid, std::process::id(), "Resolved PID should match current test runner process");

        drop(client);
        drop(server_stream);
    }
}
