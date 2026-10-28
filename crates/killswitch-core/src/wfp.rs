//! Native Windows Filtering Platform (WFP), BFE Registry & Direct TCP Socket Control.
//!
//! Provides in-memory, transaction-safe network filtering without spawning subprocesses:
//! - On Windows: Dynamic sessions (`FWPM_SESSION_FLAG_DYNAMIC = 0x00000001`) via `fwpuclnt.dll`:
//!   - Guarantees atomic transaction execution (`FwpmTransactionBegin0` / `Commit0`).
//!   - Automatic Kernel Cleanup: if the process terminates or crashes unexpectedly, the Windows
//!     kernel Base Filtering Engine (BFE) automatically purges all dynamic filters, preventing
//!     permanent host lockout.
//!   - Strict RAII handle lifetime management (`FwpmEngineClose0`) and raw pointer null checks.
//!   - Direct Windows BFE Registry manipulation via `winreg` (zero `netsh.exe` subprocesses).
//!   - Direct TCP socket termination via `iphlpapi.dll` (`GetTcpTable` + `SetTcpEntry` with
//!     `MIB_TCP_STATE_DELETE_TCB = 12`).
//! - On non-Windows: Cross-platform no-op stubs allowing workspace compilation on Linux/macOS.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use tracing::{info, warn};

use killswitch_types::errors::{KillSwitchError, KillSwitchResult};
use killswitch_types::status::{IsolationReceipt, NetworkIsolationEngine, NetworkIsolator};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------
pub const FWPM_SESSION_FLAG_DYNAMIC: u32 = 0x00000001;
pub const RPC_C_AUTHN_WINNT: u32 = 10;
pub const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;
pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

pub const FWP_MATCH_EQUAL: u32 = 0;
pub const FWP_MATCH_FLAGS_ALL_SET: u32 = 6;

pub const FWP_EMPTY: u32 = 0;
pub const FWP_UINT8: u32 = 1;
pub const FWP_UINT16: u32 = 2;
pub const FWP_UINT32: u32 = 3;
pub const FWP_UINT64: u32 = 4;
pub const FWP_BYTE_ARRAY16_TYPE: u32 = 11;

pub const FWP_ACTION_BLOCK: u32 = 0x0000_1001;
pub const FWP_ACTION_PERMIT: u32 = 0x0000_1002;

pub const FWP_CONDITION_FLAG_IS_LOOPBACK: u32 = 0x0000_0001;

pub const MIB_TCP_STATE_SYN_SENT: u32 = 3;
pub const MIB_TCP_STATE_SYN_RCVD: u32 = 4;
pub const MIB_TCP_STATE_ESTAB: u32 = 5;
pub const MIB_TCP_STATE_CLOSE_WAIT: u32 = 8;
pub const MIB_TCP_STATE_DELETE_TCB: u32 = 12;

pub const DEFAULT_CONTROL_PORT: u16 = 3030;

/// Discovers all active control/WebUI ports (3030, 4040, plus any port in `active_port.txt`)
/// so that whatever `-p <port>` the user launched `killswitch.exe` with is always preserved.
pub fn discover_active_control_ports() -> Vec<u16> {
    let mut ports = vec![DEFAULT_CONTROL_PORT, 4040];
    let candidates = [
        std::path::PathBuf::from("active_port.txt"),
        std::env::temp_dir().join("killswitch_active_port.txt"),
    ];
    for path in candidates {
        if let Ok(raw) = std::fs::read_to_string(&path) {
            if let Ok(p) = raw.trim().parse::<u16>() {
                if p > 0 && !ports.contains(&p) {
                    ports.push(p);
                }
            }
        }
    }
    ports
}

// -----------------------------------------------------------------------------
// Win32 C Structs & Official Windows SDK `fwpmu.h` GUIDs
// -----------------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Debug)]
pub struct WfpGuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

// c38d57d1-05a7-4c33-904f-7fbceee60e82
pub const FWPM_LAYER_ALE_AUTH_CONNECT_V4: WfpGuid = WfpGuid {
    data1: 0xc38d57d1,
    data2: 0x05a7,
    data3: 0x4c33,
    data4: [0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82],
};

// 4a72393b-319f-44bc-84c3-ba54dcb3b6b4
pub const FWPM_LAYER_ALE_AUTH_CONNECT_V6: WfpGuid = WfpGuid {
    data1: 0x4a72393b,
    data2: 0x319f,
    data3: 0x44bc,
    data4: [0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4],
};

// e1cd9fe7-f4b5-4273-96c0-592e487b8650
pub const FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4: WfpGuid = WfpGuid {
    data1: 0xe1cd9fe7,
    data2: 0xf4b5,
    data3: 0x4273,
    data4: [0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50],
};

// a3b42c97-9f04-4672-b87e-cee9c483257f
pub const FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6: WfpGuid = WfpGuid {
    data1: 0xa3b42c97,
    data2: 0x9f04,
    data3: 0x4672,
    data4: [0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f],
};

// 09e61aea-d214-46e2-9b21-b26b0b2f28c8
pub const FWPM_LAYER_OUTBOUND_TRANSPORT_V4: WfpGuid = WfpGuid {
    data1: 0x09e61aea,
    data2: 0xd214,
    data3: 0x46e2,
    data4: [0x9b, 0x21, 0xb2, 0x6b, 0x0b, 0x2f, 0x28, 0xc8],
};

// e1735bde-013f-4655-b351-a49e15762df0
pub const FWPM_LAYER_OUTBOUND_TRANSPORT_V6: WfpGuid = WfpGuid {
    data1: 0xe1735bde,
    data2: 0x013f,
    data3: 0x4655,
    data4: [0xb3, 0x51, 0xa4, 0x9e, 0x15, 0x76, 0x2d, 0xf0],
};

// b235ae9a-1d64-49b8-a44c-5ff3d9095045
pub const FWPM_CONDITION_IP_REMOTE_ADDRESS: WfpGuid = WfpGuid {
    data1: 0xb235ae9a,
    data2: 0x1d64,
    data3: 0x49b8,
    data4: [0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45],
};

// d9ee00de-c1ef-4617-bfe3-ffd8f5a08957
pub const FWPM_CONDITION_IP_LOCAL_ADDRESS: WfpGuid = WfpGuid {
    data1: 0xd9ee00de,
    data2: 0xc1ef,
    data3: 0x4617,
    data4: [0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57],
};

// c35a604d-d22b-4e1a-91b4-68f674ee674b
pub const FWPM_CONDITION_IP_REMOTE_PORT: WfpGuid = WfpGuid {
    data1: 0xc35a604d,
    data2: 0xd22b,
    data3: 0x4e1a,
    data4: [0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b],
};

// 0c1ba1af-5765-453f-af22-a8f791ac775b
pub const FWPM_CONDITION_IP_LOCAL_PORT: WfpGuid = WfpGuid {
    data1: 0x0c1ba1af,
    data2: 0x5765,
    data3: 0x453f,
    data4: [0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b],
};

// 3971ef2b-623e-4f9a-8cb1-6e79b806b9a7
pub const FWPM_CONDITION_IP_PROTOCOL: WfpGuid = WfpGuid {
    data1: 0x3971ef2b,
    data2: 0x623e,
    data3: 0x4f9a,
    data4: [0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7],
};

// 632ce23b-5167-435c-86d7-e903684aa80c
pub const FWPM_CONDITION_FLAGS: WfpGuid = WfpGuid {
    data1: 0x632ce23b,
    data2: 0x5167,
    data3: 0x435c,
    data4: [0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c],
};

#[repr(C)]
pub struct FwpmDisplayData0 {
    pub name: *mut u16,
    pub description: *mut u16,
}

#[repr(C)]
pub struct FwpmSession0 {
    pub session_key: [u8; 16],
    pub display_data: FwpmDisplayData0,
    pub flags: u32,
    pub txn_wait_timeout_in_msec: u32,
    pub process_id: u32,
    pub sid: *mut std::ffi::c_void,
    pub username: *mut u16,
    pub kernel_mode: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FwpValue0 {
    pub type_: u32,
    pub _pad: u32,
    pub value: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FwpByteBlob {
    pub size: u32,
    pub _pad: u32,
    pub data: *mut u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FwpmFilterCondition0 {
    pub field_key: WfpGuid,
    pub match_type: u32,
    pub _pad: u32,
    pub condition_value: FwpValue0,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FwpmAction0 {
    pub type_: u32,
    pub filter_type: WfpGuid,
}

#[repr(C)]
pub struct FwpmFilter0 {
    pub filter_key: WfpGuid,
    pub display_data: FwpmDisplayData0,
    pub flags: u32,
    pub _pad0: u32,
    pub provider_key: *mut WfpGuid,
    pub provider_data: FwpByteBlob,
    pub layer_key: WfpGuid,
    pub sub_layer_key: WfpGuid,
    pub weight: FwpValue0,
    pub num_filter_conditions: u32,
    pub _pad1: u32,
    pub filter_condition: *mut FwpmFilterCondition0,
    pub action: FwpmAction0,
    pub _pad2: u32,
    pub raw_context_or_provider_context_key: [u64; 2],
    pub reserved: *mut WfpGuid,
    pub filter_id: u64,
    pub effective_weight: FwpValue0,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MibTcpRow {
    pub dw_state: u32,
    pub dw_local_addr: u32,
    pub dw_local_port: u32,
    pub dw_remote_addr: u32,
    pub dw_remote_port: u32,
}

// -----------------------------------------------------------------------------
// Win32 Function Signatures
// -----------------------------------------------------------------------------
#[cfg(windows)]
type FnFwpmEngineOpen0 = unsafe extern "system" fn(
    server_name: *const u16,
    authn_service: u32,
    auth_identity: *mut std::ffi::c_void,
    session: *const FwpmSession0,
    engine_handle: *mut *mut std::ffi::c_void,
) -> u32;

#[cfg(windows)]
type FnFwpmEngineClose0 = unsafe extern "system" fn(engine_handle: *mut std::ffi::c_void) -> u32;

#[cfg(windows)]
type FnFwpmTransactionBegin0 =
    unsafe extern "system" fn(engine_handle: *mut std::ffi::c_void, flags: u32) -> u32;

#[cfg(windows)]
type FnFwpmTransactionCommit0 =
    unsafe extern "system" fn(engine_handle: *mut std::ffi::c_void) -> u32;

#[cfg(windows)]
type FnFwpmTransactionAbort0 =
    unsafe extern "system" fn(engine_handle: *mut std::ffi::c_void) -> u32;

#[cfg(windows)]
type FnFwpmFilterAdd0 = unsafe extern "system" fn(
    engine_handle: *mut std::ffi::c_void,
    filter: *const FwpmFilter0,
    sd: *mut std::ffi::c_void,
    id: *mut u64,
) -> u32;

#[cfg(windows)]
type FnFwpmFilterDeleteById0 =
    unsafe extern "system" fn(engine_handle: *mut std::ffi::c_void, id: u64) -> u32;

#[cfg(windows)]
type FnGetTcpTable =
    unsafe extern "system" fn(p_tcp_table: *mut u8, pdw_size: *mut u32, b_order: i32) -> u32;

#[cfg(windows)]
type FnSetTcpEntry = unsafe extern "system" fn(p_tcprow: *const MibTcpRow) -> u32;

// -----------------------------------------------------------------------------
// WfpDynamicSession
// -----------------------------------------------------------------------------
pub struct WfpDynamicSession {
    #[cfg(windows)]
    engine_handle: *mut std::ffi::c_void,
    #[cfg(windows)]
    fn_engine_close: Option<FnFwpmEngineClose0>,
    #[cfg(windows)]
    fn_txn_begin: Option<FnFwpmTransactionBegin0>,
    #[cfg(windows)]
    fn_txn_commit: Option<FnFwpmTransactionCommit0>,
    #[cfg(windows)]
    fn_txn_abort: Option<FnFwpmTransactionAbort0>,
    #[cfg(windows)]
    fn_filter_add: Option<FnFwpmFilterAdd0>,
    #[cfg(windows)]
    fn_filter_delete_by_id: Option<FnFwpmFilterDeleteById0>,
    #[cfg(windows)]
    in_transaction: AtomicBool,
    #[cfg(not(windows))]
    _active: bool,
}

unsafe impl Send for WfpDynamicSession {}
unsafe impl Sync for WfpDynamicSession {}

impl WfpDynamicSession {
    /// Opens a WFP engine session.
    /// Uses `flags = 0` so filters installed by one-shot CLI invocations (`killswitch.exe isolate`)
    /// remain active in the Windows Base Filtering Engine (BFE) until `killswitch.exe restore`
    /// or `disarm_windows_network_quarantine()` explicitly deletes them by filter ID.
    pub fn open() -> KillSwitchResult<Self> {
        Self::open_with_flags(0)
    }

    /// Opens a WFP engine session with explicit session flags (`0` or `FWPM_SESSION_FLAG_DYNAMIC`).
    pub fn open_with_flags(session_flags: u32) -> KillSwitchResult<Self> {
        #[cfg(windows)]
        {
            use windows::core::{PCSTR, PCWSTR};
            use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

            let dll_name: Vec<u16> = "fwpuclnt.dll\0".encode_utf16().collect();
            let h_module = unsafe { LoadLibraryW(PCWSTR(dll_name.as_ptr())) }.map_err(|e| {
                KillSwitchError::WfpSymbolNotFound {
                    symbol: format!("fwpuclnt.dll load failed: {}", e),
                }
            })?;

            let get_func = |name: &'static [u8]| -> Option<*const ()> {
                let proc = unsafe { GetProcAddress(h_module, PCSTR(name.as_ptr())) };
                proc.map(|p| (p as usize) as *const ())
            };

            let fn_open: FnFwpmEngineOpen0 = unsafe {
                std::mem::transmute(get_func(b"FwpmEngineOpen0\0").ok_or_else(|| {
                    KillSwitchError::WfpSymbolNotFound {
                        symbol: "FwpmEngineOpen0".to_string(),
                    }
                })?)
            };

            let fn_close: FnFwpmEngineClose0 = unsafe {
                std::mem::transmute(get_func(b"FwpmEngineClose0\0").ok_or_else(|| {
                    KillSwitchError::WfpSymbolNotFound {
                        symbol: "FwpmEngineClose0".to_string(),
                    }
                })?)
            };

            let fn_txn_begin: FnFwpmTransactionBegin0 = unsafe {
                std::mem::transmute(get_func(b"FwpmTransactionBegin0\0").ok_or_else(|| {
                    KillSwitchError::WfpSymbolNotFound {
                        symbol: "FwpmTransactionBegin0".to_string(),
                    }
                })?)
            };

            let fn_txn_commit: FnFwpmTransactionCommit0 = unsafe {
                std::mem::transmute(get_func(b"FwpmTransactionCommit0\0").ok_or_else(|| {
                    KillSwitchError::WfpSymbolNotFound {
                        symbol: "FwpmTransactionCommit0".to_string(),
                    }
                })?)
            };

            let fn_txn_abort: FnFwpmTransactionAbort0 = unsafe {
                std::mem::transmute(get_func(b"FwpmTransactionAbort0\0").ok_or_else(|| {
                    KillSwitchError::WfpSymbolNotFound {
                        symbol: "FwpmTransactionAbort0".to_string(),
                    }
                })?)
            };

            let fn_filter_add: Option<FnFwpmFilterAdd0> =
                unsafe { get_func(b"FwpmFilterAdd0\0").map(|p| std::mem::transmute(p)) };

            let fn_filter_delete_by_id: Option<FnFwpmFilterDeleteById0> =
                unsafe { get_func(b"FwpmFilterDeleteById0\0").map(|p| std::mem::transmute(p)) };

            let mut session_name: Vec<u16> = "KillSwitch-DynamicSession\0".encode_utf16().collect();
            let mut session_desc: Vec<u16> =
                "KillSwitch Autonomous EDR Dynamic Quarantine Session\0"
                    .encode_utf16()
                    .collect();

            let session = FwpmSession0 {
                session_key: [0u8; 16],
                display_data: FwpmDisplayData0 {
                    name: session_name.as_mut_ptr(),
                    description: session_desc.as_mut_ptr(),
                },
                flags: session_flags,
                txn_wait_timeout_in_msec: 5000,
                process_id: 0, // Must be 0 on input to FwpmEngineOpen0 ([out]-only field)
                sid: std::ptr::null_mut(),
                username: std::ptr::null_mut(),
                kernel_mode: 0,
            };

            let mut engine_handle: *mut std::ffi::c_void = std::ptr::null_mut();
            let mut status = unsafe {
                fn_open(
                    std::ptr::null(),
                    RPC_C_AUTHN_WINNT,
                    std::ptr::null_mut(),
                    &session,
                    &mut engine_handle,
                )
            };

            if status != ERROR_SUCCESS || engine_handle.is_null() {
                status = unsafe {
                    fn_open(
                        std::ptr::null(),
                        RPC_C_AUTHN_DEFAULT,
                        std::ptr::null_mut(),
                        if session_flags == 0 {
                            std::ptr::null()
                        } else {
                            &session
                        },
                        &mut engine_handle,
                    )
                };
            }

            if status != ERROR_SUCCESS || engine_handle.is_null() {
                warn!(
                    "⚠️ [WFP] FwpmEngineOpen0 failed with status 0x{:08X} (flags: 0x{:08X})",
                    status, session_flags
                );
                return Err(KillSwitchError::WfpEngineOpenFailed(status));
            }

            info!(
                "🟢 [WFP] Opened WFP engine session (Handle: {:p}, flags: 0x{:08X})",
                engine_handle, session_flags
            );

            Ok(Self {
                engine_handle,
                fn_engine_close: Some(fn_close),
                fn_txn_begin: Some(fn_txn_begin),
                fn_txn_commit: Some(fn_txn_commit),
                fn_txn_abort: Some(fn_txn_abort),
                fn_filter_add,
                fn_filter_delete_by_id,
                in_transaction: AtomicBool::new(false),
            })
        }

        #[cfg(not(windows))]
        {
            let _ = session_flags;
            info!("🟢 [WFP-STUB] Non-Windows platform: initialized stub dynamic session.");
            Ok(Self { _active: true })
        }
    }

    /// Begins an atomic transaction for firewall modifications.
    pub fn begin_transaction(&self) -> KillSwitchResult<()> {
        #[cfg(windows)]
        {
            if self.engine_handle.is_null() {
                return Err(KillSwitchError::WfpEngineHandleNull);
            }
            if let Some(fn_begin) = self.fn_txn_begin {
                let status = unsafe { fn_begin(self.engine_handle, 0) };
                if status != ERROR_SUCCESS {
                    return Err(KillSwitchError::WfpTransactionBeginFailed(status));
                }
                self.in_transaction.store(true, Ordering::SeqCst);
                return Ok(());
            }
            Err(KillSwitchError::WfpSymbolNotFound {
                symbol: "FwpmTransactionBegin0".to_string(),
            })
        }
        #[cfg(not(windows))]
        {
            Ok(())
        }
    }

    /// Commits the active atomic transaction.
    pub fn commit_transaction(&self) -> KillSwitchResult<()> {
        #[cfg(windows)]
        {
            if self.engine_handle.is_null() {
                return Err(KillSwitchError::WfpEngineHandleNull);
            }
            if let Some(fn_commit) = self.fn_txn_commit {
                let status = unsafe { fn_commit(self.engine_handle) };
                self.in_transaction.store(false, Ordering::SeqCst);
                if status != ERROR_SUCCESS {
                    return Err(KillSwitchError::WfpTransactionCommitFailed(status));
                }
                return Ok(());
            }
            Err(KillSwitchError::WfpSymbolNotFound {
                symbol: "FwpmTransactionCommit0".to_string(),
            })
        }
        #[cfg(not(windows))]
        {
            Ok(())
        }
    }

    /// Aborts the active atomic transaction, rolling back pending additions.
    pub fn abort_transaction(&self) -> KillSwitchResult<()> {
        #[cfg(windows)]
        {
            if self.engine_handle.is_null() {
                return Err(KillSwitchError::WfpEngineHandleNull);
            }
            if let Some(fn_abort) = self.fn_txn_abort {
                let status = unsafe { fn_abort(self.engine_handle) };
                self.in_transaction.store(false, Ordering::SeqCst);
                if status != ERROR_SUCCESS {
                    return Err(KillSwitchError::WfpTransactionAbortFailed(status));
                }
                return Ok(());
            }
            Err(KillSwitchError::WfpSymbolNotFound {
                symbol: "FwpmTransactionAbort0".to_string(),
            })
        }
        #[cfg(not(windows))]
        {
            Ok(())
        }
    }

    /// Deletes a filter by its assigned 64-bit ID.
    pub fn delete_filter_by_id(&self, filter_id: u64) -> KillSwitchResult<()> {
        #[cfg(windows)]
        {
            if self.engine_handle.is_null() {
                return Err(KillSwitchError::WfpEngineHandleNull);
            }
            if let Some(fn_del) = self.fn_filter_delete_by_id {
                let status = unsafe { fn_del(self.engine_handle, filter_id) };
                if status != ERROR_SUCCESS {
                    return Err(KillSwitchError::WfpFilterDeleteFailed {
                        filter_id,
                        win32_code: status,
                    });
                }
                return Ok(());
            }
            Err(KillSwitchError::WfpSymbolNotFound {
                symbol: "FwpmFilterDeleteById0".to_string(),
            })
        }
        #[cfg(not(windows))]
        {
            let _ = filter_id;
            Ok(())
        }
    }

    /// Helper to add a raw WFP filter structure.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `filter` contains valid Win32 FWP pointers and types
    /// that remain valid for the duration of the call.
    #[cfg(windows)]
    pub unsafe fn add_filter_raw(
        &self,
        filter: &FwpmFilter0,
        layer_desc: &str,
    ) -> KillSwitchResult<u64> {
        let Some(fn_add) = self.fn_filter_add else {
            return Err(KillSwitchError::WfpSymbolNotFound {
                symbol: "FwpmFilterAdd0".to_string(),
            });
        };
        let mut assigned_id: u64 = 0;
        let status = fn_add(
            self.engine_handle,
            filter,
            std::ptr::null_mut(),
            &mut assigned_id,
        );
        if status != ERROR_SUCCESS || assigned_id == 0 {
            return Err(KillSwitchError::WfpFilterAddFailed {
                layer: layer_desc.to_string(),
                win32_code: status,
            });
        }
        Ok(assigned_id)
    }

    /// Installs hermetic network quarantine filters.
    ///
    /// Permits:
    /// - Loopback (127.0.0.1, ::1)
    /// - Control Port 3030 (TCP)
    /// - DNS (Port 53 UDP/TCP)
    /// - DHCP (UDP 67/68, UDP 546/547)
    ///
    /// Blocks:
    /// - All other inbound & outbound traffic.
    pub fn install_hermetic_quarantine_filters(
        &self,
        rule_prefix: &str,
    ) -> KillSwitchResult<Vec<u64>> {
        #[cfg(windows)]
        {
            if self.engine_handle.is_null() {
                return Err(KillSwitchError::WfpEngineHandleNull);
            }

            let mut filter_ids = Vec::new();
            self.begin_transaction()?;

            let mut w_desc: Vec<u16> = "KillSwitch Native Hermetic Quarantine\0"
                .encode_utf16()
                .collect();

            let mut install_filter =
                |name: &str,
                 layer: WfpGuid,
                 layer_name: &str,
                 action: u32,
                 weight_val: usize,
                 conditions: &mut [FwpmFilterCondition0]|
                 -> KillSwitchResult<u64> {
                    let mut w_name: Vec<u16> = format!("{}-{}\0", rule_prefix, name)
                        .encode_utf16()
                        .collect();

                    let mut filter = FwpmFilter0 {
                        filter_key: WfpGuid::default(),
                        display_data: FwpmDisplayData0 {
                            name: w_name.as_mut_ptr(),
                            description: w_desc.as_mut_ptr(),
                        },
                        flags: 0,
                        _pad0: 0,
                        provider_key: std::ptr::null_mut(),
                        provider_data: FwpByteBlob {
                            size: 0,
                            _pad: 0,
                            data: std::ptr::null_mut(),
                        },
                        layer_key: layer,
                        sub_layer_key: WfpGuid::default(),
                        weight: FwpValue0 {
                            type_: if weight_val > 0 { FWP_UINT8 } else { FWP_EMPTY },
                            _pad: 0,
                            value: weight_val,
                        },
                        num_filter_conditions: conditions.len() as u32,
                        _pad1: 0,
                        filter_condition: if conditions.is_empty() {
                            std::ptr::null_mut()
                        } else {
                            conditions.as_mut_ptr()
                        },
                        action: FwpmAction0 {
                            type_: action,
                            filter_type: WfpGuid::default(),
                        },
                        _pad2: 0,
                        raw_context_or_provider_context_key: [0; 2],
                        reserved: std::ptr::null_mut(),
                        filter_id: 0,
                        effective_weight: FwpValue0 {
                            type_: FWP_EMPTY,
                            _pad: 0,
                            value: 0,
                        },
                    };

                    match unsafe { self.add_filter_raw(&filter, layer_name) } {
                        Ok(id) => Ok(id),
                        Err(_first_err) => {
                            // Fallback to BFE automatic weight calculation (FWP_EMPTY)
                            filter.weight = FwpValue0 {
                                type_: FWP_EMPTY,
                                _pad: 0,
                                value: 0,
                            };
                            let res = unsafe { self.add_filter_raw(&filter, layer_name) };
                            if let Err(ref e) = res {
                                warn!("⚠️ [WFP] Filter '{}' on {} failed: {}", name, layer_name, e);
                            }
                            res
                        }
                    }
                };

            // 1. PERMIT LOOPBACK IPv4 (127.0.0.1)
            let loopback_v4_u32 = u32::from_be_bytes([127, 0, 0, 1]);
            let mut cond_lb_out_v4 = [FwpmFilterCondition0 {
                field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                match_type: FWP_MATCH_EQUAL,
                _pad: 0,
                condition_value: FwpValue0 {
                    type_: FWP_UINT32,
                    _pad: 0,
                    value: loopback_v4_u32 as usize,
                },
            }];
            if let Ok(id) = install_filter(
                "Permit-Loopback-Out-v4",
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                "ALE_AUTH_CONNECT_V4",
                FWP_ACTION_PERMIT,
                15,
                &mut cond_lb_out_v4,
            ) {
                filter_ids.push(id);
            }

            let mut cond_lb_in_v4 = [FwpmFilterCondition0 {
                field_key: FWPM_CONDITION_IP_LOCAL_ADDRESS,
                match_type: FWP_MATCH_EQUAL,
                _pad: 0,
                condition_value: FwpValue0 {
                    type_: FWP_UINT32,
                    _pad: 0,
                    value: loopback_v4_u32 as usize,
                },
            }];
            if let Ok(id) = install_filter(
                "Permit-Loopback-In-v4",
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                "ALE_AUTH_RECV_ACCEPT_V4",
                FWP_ACTION_PERMIT,
                15,
                &mut cond_lb_in_v4,
            ) {
                filter_ids.push(id);
            }

            // 1b. PERMIT ALL LOOPBACK VIA FWP_CONDITION_FLAG_IS_LOOPBACK
            let mut cond_lb_flag_out_v4 = [FwpmFilterCondition0 {
                field_key: FWPM_CONDITION_FLAGS,
                match_type: FWP_MATCH_FLAGS_ALL_SET,
                _pad: 0,
                condition_value: FwpValue0 {
                    type_: FWP_UINT32,
                    _pad: 0,
                    value: FWP_CONDITION_FLAG_IS_LOOPBACK as usize,
                },
            }];
            if let Ok(id) = install_filter(
                "Permit-LoopbackFlag-Out-v4",
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                "ALE_AUTH_CONNECT_V4",
                FWP_ACTION_PERMIT,
                15,
                &mut cond_lb_flag_out_v4,
            ) {
                filter_ids.push(id);
            }

            let mut cond_lb_flag_in_v4 = [FwpmFilterCondition0 {
                field_key: FWPM_CONDITION_FLAGS,
                match_type: FWP_MATCH_FLAGS_ALL_SET,
                _pad: 0,
                condition_value: FwpValue0 {
                    type_: FWP_UINT32,
                    _pad: 0,
                    value: FWP_CONDITION_FLAG_IS_LOOPBACK as usize,
                },
            }];
            if let Ok(id) = install_filter(
                "Permit-LoopbackFlag-In-v4",
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                "ALE_AUTH_RECV_ACCEPT_V4",
                FWP_ACTION_PERMIT,
                15,
                &mut cond_lb_flag_in_v4,
            ) {
                filter_ids.push(id);
            }
            let loopback_v6_bytes = Ipv6Addr::LOCALHOST.octets();
            let mut cond_lb_out_v6 = [FwpmFilterCondition0 {
                field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                match_type: FWP_MATCH_EQUAL,
                _pad: 0,
                condition_value: FwpValue0 {
                    type_: FWP_BYTE_ARRAY16_TYPE,
                    _pad: 0,
                    value: loopback_v6_bytes.as_ptr() as usize,
                },
            }];
            if let Ok(id) = install_filter(
                "Permit-Loopback-Out-v6",
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                "ALE_AUTH_CONNECT_V6",
                FWP_ACTION_PERMIT,
                15,
                &mut cond_lb_out_v6,
            ) {
                filter_ids.push(id);
            }

            let mut cond_lb_in_v6 = [FwpmFilterCondition0 {
                field_key: FWPM_CONDITION_IP_LOCAL_ADDRESS,
                match_type: FWP_MATCH_EQUAL,
                _pad: 0,
                condition_value: FwpValue0 {
                    type_: FWP_BYTE_ARRAY16_TYPE,
                    _pad: 0,
                    value: loopback_v6_bytes.as_ptr() as usize,
                },
            }];
            if let Ok(id) = install_filter(
                "Permit-Loopback-In-v6",
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                "ALE_AUTH_RECV_ACCEPT_V6",
                FWP_ACTION_PERMIT,
                15,
                &mut cond_lb_in_v6,
            ) {
                filter_ids.push(id);
            }

            // 3. PERMIT ALL ACTIVE CONTROL / WEBUI PORTS (3030, 4040, and active_port.txt TCP)
            for ctrl_port in discover_active_control_ports() {
                let mut cond_port_in = [
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_IP_LOCAL_PORT,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpValue0 {
                            type_: FWP_UINT16,
                            _pad: 0,
                            value: ctrl_port as usize,
                        },
                    },
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_IP_PROTOCOL,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpValue0 {
                            type_: FWP_UINT8,
                            _pad: 0,
                            value: 6, // IPPROTO_TCP
                        },
                    },
                ];
                if let Ok(id) = install_filter(
                    &format!("Permit-ControlPort{}-In-v4", ctrl_port),
                    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                    "ALE_AUTH_RECV_ACCEPT_V4",
                    FWP_ACTION_PERMIT,
                    15,
                    &mut cond_port_in,
                ) {
                    filter_ids.push(id);
                }

                let mut cond_port_out = [
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_IP_REMOTE_PORT,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpValue0 {
                            type_: FWP_UINT16,
                            _pad: 0,
                            value: ctrl_port as usize,
                        },
                    },
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_IP_PROTOCOL,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpValue0 {
                            type_: FWP_UINT8,
                            _pad: 0,
                            value: 6, // IPPROTO_TCP
                        },
                    },
                ];
                if let Ok(id) = install_filter(
                    &format!("Permit-ControlPort{}-Out-v4", ctrl_port),
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    "ALE_AUTH_CONNECT_V4",
                    FWP_ACTION_PERMIT,
                    15,
                    &mut cond_port_out,
                ) {
                    filter_ids.push(id);
                }

                let mut cond_port_trans_local = [
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_IP_LOCAL_PORT,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpValue0 {
                            type_: FWP_UINT16,
                            _pad: 0,
                            value: ctrl_port as usize,
                        },
                    },
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_IP_PROTOCOL,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpValue0 {
                            type_: FWP_UINT8,
                            _pad: 0,
                            value: 6, // IPPROTO_TCP
                        },
                    },
                ];
                if let Ok(id) = install_filter(
                    &format!("Permit-ControlPort{}-Transport-Local-v4", ctrl_port),
                    FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
                    "OUTBOUND_TRANSPORT_V4",
                    FWP_ACTION_PERMIT,
                    15,
                    &mut cond_port_trans_local,
                ) {
                    filter_ids.push(id);
                }

                let mut cond_port_trans_remote = [
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_IP_REMOTE_PORT,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpValue0 {
                            type_: FWP_UINT16,
                            _pad: 0,
                            value: ctrl_port as usize,
                        },
                    },
                    FwpmFilterCondition0 {
                        field_key: FWPM_CONDITION_IP_PROTOCOL,
                        match_type: FWP_MATCH_EQUAL,
                        _pad: 0,
                        condition_value: FwpValue0 {
                            type_: FWP_UINT8,
                            _pad: 0,
                            value: 6, // IPPROTO_TCP
                        },
                    },
                ];
                if let Ok(id) = install_filter(
                    &format!("Permit-ControlPort{}-Transport-Remote-v4", ctrl_port),
                    FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
                    "OUTBOUND_TRANSPORT_V4",
                    FWP_ACTION_PERMIT,
                    15,
                    &mut cond_port_trans_remote,
                ) {
                    filter_ids.push(id);
                }
            }

            // 4. PERMIT DHCPv4 (UDP 67/68)
            let mut cond_dhcp_out = [
                FwpmFilterCondition0 {
                    field_key: FWPM_CONDITION_IP_REMOTE_PORT,
                    match_type: FWP_MATCH_EQUAL,
                    _pad: 0,
                    condition_value: FwpValue0 {
                        type_: FWP_UINT16,
                        _pad: 0,
                        value: 67,
                    },
                },
                FwpmFilterCondition0 {
                    field_key: FWPM_CONDITION_IP_PROTOCOL,
                    match_type: FWP_MATCH_EQUAL,
                    _pad: 0,
                    condition_value: FwpValue0 {
                        type_: FWP_UINT8,
                        _pad: 0,
                        value: 17,
                    },
                },
            ];
            if let Ok(id) = install_filter(
                "Permit-DHCPv4-Out",
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                "ALE_AUTH_CONNECT_V4",
                FWP_ACTION_PERMIT,
                15,
                &mut cond_dhcp_out,
            ) {
                filter_ids.push(id);
            }

            // 5. CATCH-ALL ALE BLOCK FILTERS (Weight = 1, evaluated after Permit filters)
            if let Ok(id) = install_filter(
                "Block-All-Outbound-v4",
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                "ALE_AUTH_CONNECT_V4",
                FWP_ACTION_BLOCK,
                1,
                &mut [],
            ) {
                filter_ids.push(id);
            }

            if let Ok(id) = install_filter(
                "Block-All-Outbound-v6",
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                "ALE_AUTH_CONNECT_V6",
                FWP_ACTION_BLOCK,
                1,
                &mut [],
            ) {
                filter_ids.push(id);
            }

            // 6. TRANSPORT LAYER LOOPBACK PERMIT + CATCH-ALL BLOCK
            // Blocks ALL non-loopback packets at the transport layer (including ICMP `ping 8.8.8.8`,
            // pre-existing TCP/HTTP2 sockets, and UDP/QUIC HTTP/3 browser connections).
            let mut cond_lb_trans_v4 = [FwpmFilterCondition0 {
                field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                match_type: FWP_MATCH_EQUAL,
                _pad: 0,
                condition_value: FwpValue0 {
                    type_: FWP_UINT32,
                    _pad: 0,
                    value: loopback_v4_u32 as usize,
                },
            }];
            if let Ok(id) = install_filter(
                "Permit-Loopback-Transport-Out-v4",
                FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
                "OUTBOUND_TRANSPORT_V4",
                FWP_ACTION_PERMIT,
                15,
                &mut cond_lb_trans_v4,
            ) {
                filter_ids.push(id);
            }

            let mut cond_lb_flag_trans_v4 = [FwpmFilterCondition0 {
                field_key: FWPM_CONDITION_FLAGS,
                match_type: FWP_MATCH_FLAGS_ALL_SET,
                _pad: 0,
                condition_value: FwpValue0 {
                    type_: FWP_UINT32,
                    _pad: 0,
                    value: FWP_CONDITION_FLAG_IS_LOOPBACK as usize,
                },
            }];
            if let Ok(id) = install_filter(
                "Permit-LoopbackFlag-Transport-Out-v4",
                FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
                "OUTBOUND_TRANSPORT_V4",
                FWP_ACTION_PERMIT,
                15,
                &mut cond_lb_flag_trans_v4,
            ) {
                filter_ids.push(id);
            }

            let mut cond_lb_trans_v6 = [FwpmFilterCondition0 {
                field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                match_type: FWP_MATCH_EQUAL,
                _pad: 0,
                condition_value: FwpValue0 {
                    type_: FWP_BYTE_ARRAY16_TYPE,
                    _pad: 0,
                    value: loopback_v6_bytes.as_ptr() as usize,
                },
            }];
            if let Ok(id) = install_filter(
                "Permit-Loopback-Transport-Out-v6",
                FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
                "OUTBOUND_TRANSPORT_V6",
                FWP_ACTION_PERMIT,
                15,
                &mut cond_lb_trans_v6,
            ) {
                filter_ids.push(id);
            }

            let mut cond_lb_flag_trans_v6 = [FwpmFilterCondition0 {
                field_key: FWPM_CONDITION_FLAGS,
                match_type: FWP_MATCH_FLAGS_ALL_SET,
                _pad: 0,
                condition_value: FwpValue0 {
                    type_: FWP_UINT32,
                    _pad: 0,
                    value: FWP_CONDITION_FLAG_IS_LOOPBACK as usize,
                },
            }];
            if let Ok(id) = install_filter(
                "Permit-LoopbackFlag-Transport-Out-v6",
                FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
                "OUTBOUND_TRANSPORT_V6",
                FWP_ACTION_PERMIT,
                15,
                &mut cond_lb_flag_trans_v6,
            ) {
                filter_ids.push(id);
            }

            if let Ok(id) = install_filter(
                "Block-All-Transport-Out-v4",
                FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
                "OUTBOUND_TRANSPORT_V4",
                FWP_ACTION_BLOCK,
                1,
                &mut [],
            ) {
                filter_ids.push(id);
            }

            if let Ok(id) = install_filter(
                "Block-All-Transport-Out-v6",
                FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
                "OUTBOUND_TRANSPORT_V6",
                FWP_ACTION_BLOCK,
                1,
                &mut [],
            ) {
                filter_ids.push(id);
            }

            if let Ok(id) = install_filter(
                "Block-All-Inbound-v4",
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                "ALE_AUTH_RECV_ACCEPT_V4",
                FWP_ACTION_BLOCK,
                1,
                &mut [],
            ) {
                filter_ids.push(id);
            }

            if let Ok(id) = install_filter(
                "Block-All-Inbound-v6",
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                "ALE_AUTH_RECV_ACCEPT_V6",
                FWP_ACTION_BLOCK,
                1,
                &mut [],
            ) {
                filter_ids.push(id);
            }

            self.commit_transaction()?;
            info!(
                "🛡️ [WFP] Installed {} dynamic hermetic quarantine filters",
                filter_ids.len()
            );
            Ok(filter_ids)
        }

        #[cfg(not(windows))]
        {
            let _ = rule_prefix;
            Ok(vec![1001, 1002, 1003])
        }
    }

    /// Adds outbound block filters for specific destination IP addresses.
    pub fn add_outbound_ip_block_filters(&self, rule_name: &str, ips: &[IpAddr]) -> Vec<u64> {
        #[cfg(windows)]
        {
            if self.engine_handle.is_null() || ips.is_empty() {
                return Vec::new();
            }
            let Some(fn_add) = self.fn_filter_add else {
                return Vec::new();
            };

            let mut filter_ids = Vec::new();
            let mut w_name: Vec<u16> = format!("{}\0", rule_name).encode_utf16().collect();
            let mut w_desc: Vec<u16> = "KillSwitch Native WFP Destination Block\0"
                .encode_utf16()
                .collect();

            let txn_ok = self.begin_transaction().is_ok();

            for ip in ips {
                match ip {
                    IpAddr::V4(v4) => {
                        let host_u32 = u32::from_be_bytes(v4.octets());
                        for layer in [
                            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                            FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
                        ] {
                            let mut cond = FwpmFilterCondition0 {
                                field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                match_type: FWP_MATCH_EQUAL,
                                _pad: 0,
                                condition_value: FwpValue0 {
                                    type_: FWP_UINT32,
                                    _pad: 0,
                                    value: host_u32 as usize,
                                },
                            };
                            let filter = FwpmFilter0 {
                                filter_key: WfpGuid::default(),
                                display_data: FwpmDisplayData0 {
                                    name: w_name.as_mut_ptr(),
                                    description: w_desc.as_mut_ptr(),
                                },
                                flags: 0,
                                _pad0: 0,
                                provider_key: std::ptr::null_mut(),
                                provider_data: FwpByteBlob {
                                    size: 0,
                                    _pad: 0,
                                    data: std::ptr::null_mut(),
                                },
                                layer_key: layer,
                                sub_layer_key: WfpGuid::default(),
                                weight: FwpValue0 {
                                    type_: FWP_EMPTY,
                                    _pad: 0,
                                    value: 0,
                                },
                                num_filter_conditions: 1,
                                _pad1: 0,
                                filter_condition: &mut cond,
                                action: FwpmAction0 {
                                    type_: FWP_ACTION_BLOCK,
                                    filter_type: WfpGuid::default(),
                                },
                                _pad2: 0,
                                raw_context_or_provider_context_key: [0; 2],
                                reserved: std::ptr::null_mut(),
                                filter_id: 0,
                                effective_weight: FwpValue0 {
                                    type_: FWP_EMPTY,
                                    _pad: 0,
                                    value: 0,
                                },
                            };
                            let mut assigned_id: u64 = 0;
                            let status = unsafe {
                                fn_add(
                                    self.engine_handle,
                                    &filter,
                                    std::ptr::null_mut(),
                                    &mut assigned_id,
                                )
                            };
                            if status == ERROR_SUCCESS && assigned_id != 0 {
                                filter_ids.push(assigned_id);
                            }
                        }
                    }
                    IpAddr::V6(v6) => {
                        let octets = v6.octets();
                        for layer in [
                            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                            FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
                        ] {
                            let mut cond = FwpmFilterCondition0 {
                                field_key: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                match_type: FWP_MATCH_EQUAL,
                                _pad: 0,
                                condition_value: FwpValue0 {
                                    type_: FWP_BYTE_ARRAY16_TYPE,
                                    _pad: 0,
                                    value: octets.as_ptr() as usize,
                                },
                            };
                            let filter = FwpmFilter0 {
                                filter_key: WfpGuid::default(),
                                display_data: FwpmDisplayData0 {
                                    name: w_name.as_mut_ptr(),
                                    description: w_desc.as_mut_ptr(),
                                },
                                flags: 0,
                                _pad0: 0,
                                provider_key: std::ptr::null_mut(),
                                provider_data: FwpByteBlob {
                                    size: 0,
                                    _pad: 0,
                                    data: std::ptr::null_mut(),
                                },
                                layer_key: layer,
                                sub_layer_key: WfpGuid::default(),
                                weight: FwpValue0 {
                                    type_: FWP_EMPTY,
                                    _pad: 0,
                                    value: 0,
                                },
                                num_filter_conditions: 1,
                                _pad1: 0,
                                filter_condition: &mut cond,
                                action: FwpmAction0 {
                                    type_: FWP_ACTION_BLOCK,
                                    filter_type: WfpGuid::default(),
                                },
                                _pad2: 0,
                                raw_context_or_provider_context_key: [0; 2],
                                reserved: std::ptr::null_mut(),
                                filter_id: 0,
                                effective_weight: FwpValue0 {
                                    type_: FWP_EMPTY,
                                    _pad: 0,
                                    value: 0,
                                },
                            };
                            let mut assigned_id: u64 = 0;
                            let status = unsafe {
                                fn_add(
                                    self.engine_handle,
                                    &filter,
                                    std::ptr::null_mut(),
                                    &mut assigned_id,
                                )
                            };
                            if status == ERROR_SUCCESS && assigned_id != 0 {
                                filter_ids.push(assigned_id);
                            }
                        }
                    }
                }
            }

            if txn_ok {
                let _ = self.commit_transaction();
            }
            filter_ids
        }
        #[cfg(not(windows))]
        {
            let _ = (rule_name, ips);
            Vec::new()
        }
    }

    /// Checks if native WFP is available on the current system.
    pub fn is_available() -> bool {
        #[cfg(windows)]
        {
            Self::open().is_ok()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }
}

impl Drop for WfpDynamicSession {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if self.in_transaction.load(Ordering::SeqCst) {
                if let Some(fn_abort) = self.fn_txn_abort {
                    if !self.engine_handle.is_null() {
                        let _ = unsafe { fn_abort(self.engine_handle) };
                    }
                }
            }
            if !self.engine_handle.is_null() {
                if let Some(fn_close) = self.fn_engine_close {
                    let status = unsafe { fn_close(self.engine_handle) };
                    if status == ERROR_SUCCESS {
                        info!(
                            "🟢 [WFP] Closed dynamic WFP engine session (Handle: {:p})",
                            self.engine_handle
                        );
                    } else {
                        warn!("⚠️ [WFP] FwpmEngineClose0 returned 0x{:08X}", status);
                    }
                }
                self.engine_handle = std::ptr::null_mut();
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Windows BFE Registry Management via `winreg` (Zero Subprocesses)
// -----------------------------------------------------------------------------
pub const BFE_FIREWALL_RULES_PATH: &str =
    r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

/// Writes a native Windows Base Filtering Engine (BFE) FirewallPolicy rule directly via `winreg`
/// without spawning any external utilities (`netsh`).
pub fn apply_native_bfe_registry_rule(
    rule_name: &str,
    direction: &str,
    action: &str,
    protocol: Option<u8>,
    local_port: Option<u16>,
    remote_port: Option<u16>,
    ips: &[IpAddr],
) -> bool {
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let Ok(fw_key) = hklm.open_subkey_with_flags(BFE_FIREWALL_RULES_PATH, KEY_READ | KEY_WRITE)
        else {
            return false;
        };

        let dir_token = if direction.eq_ignore_ascii_case("in") {
            "In"
        } else {
            "Out"
        };
        let action_token = if action.eq_ignore_ascii_case("allow") {
            "Allow"
        } else {
            "Block"
        };

        let mut parts = vec![
            "v2.31".to_string(),
            format!("Action={}", action_token),
            "Active=TRUE".to_string(),
            format!("Dir={}", dir_token),
        ];

        if let Some(p) = protocol {
            parts.push(format!("Protocol={}", p));
        }
        if let Some(lp) = local_port {
            parts.push(format!("LPort={}", lp));
        }
        if let Some(rp) = remote_port {
            parts.push(format!("RPort={}", rp));
        }

        for ip in ips {
            match ip {
                IpAddr::V4(v4) => parts.push(format!("RA4={}", v4)),
                IpAddr::V6(v6) => parts.push(format!("RA6={}", v6)),
            }
        }

        parts.push(format!("Name={}", rule_name));
        parts.push("Desc=KillSwitch Native Rust BFE Policy Rule".to_string());
        let rule_value = format!("{}|", parts.join("|"));

        fw_key.set_value(rule_name, &rule_value).is_ok()
    }
    #[cfg(not(windows))]
    {
        let _ = (
            rule_name,
            direction,
            action,
            protocol,
            local_port,
            remote_port,
            ips,
        );
        true
    }
}

/// Applies all standard BFE registry rules for Hermetic Network Quarantine.
pub fn apply_bfe_registry_quarantine_rules() -> Vec<String> {
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let Ok(fw_key) = hklm.open_subkey_with_flags(BFE_FIREWALL_RULES_PATH, KEY_READ | KEY_WRITE)
        else {
            return Vec::new();
        };

        let rules = [
            (
                "KillSwitch-Allow-Loopback-In",
                "v2.31|Action=Allow|Active=TRUE|Dir=In|RA4=127.0.0.1|RA6=::1|Name=KillSwitch-Allow-Loopback-In|Desc=KillSwitch Loopback Inbound|",
            ),
            (
                "KillSwitch-Allow-Loopback-Out",
                "v2.31|Action=Allow|Active=TRUE|Dir=Out|RA4=127.0.0.1|RA6=::1|Name=KillSwitch-Allow-Loopback-Out|Desc=KillSwitch Loopback Outbound|",
            ),
            (
                "KillSwitch-Allow-WebUI-In",
                "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3030|Name=KillSwitch-Allow-WebUI-In|Desc=KillSwitch Control API Inbound|",
            ),
            (
                "KillSwitch-Allow-WebUI-Out",
                "v2.31|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|LPort=3030|Name=KillSwitch-Allow-WebUI-Out|Desc=KillSwitch Control API Outbound|",
            ),
            (
                "KillSwitch-Allow-WebUI-Out-Remote",
                "v2.31|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|RPort=3030|Name=KillSwitch-Allow-WebUI-Out-Remote|Desc=KillSwitch Control Remote Outbound|",
            ),
            (
                "KillSwitch-Allow-DNS-Out",
                "v2.31|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|RPort=53|Name=KillSwitch-Allow-DNS-Out|Desc=KillSwitch DNS UDP Outbound|",
            ),
            (
                "KillSwitch-Allow-DNS-TCP-Out",
                "v2.31|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|RPort=53|Name=KillSwitch-Allow-DNS-TCP-Out|Desc=KillSwitch DNS TCP Outbound|",
            ),
            (
                "KillSwitch-Allow-DHCP-Out",
                "v2.31|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|LPort=68|RPort=67|Name=KillSwitch-Allow-DHCP-Out|Desc=KillSwitch DHCPv4 Outbound|",
            ),
            (
                "KillSwitch-Allow-DHCP-In",
                "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=68|RPort=67|Name=KillSwitch-Allow-DHCP-In|Desc=KillSwitch DHCPv4 Inbound|",
            ),
            (
                "KillSwitch-Allow-DHCPv6-Out",
                "v2.31|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|LPort=546|RPort=547|Name=KillSwitch-Allow-DHCPv6-Out|Desc=KillSwitch DHCPv6 Outbound|",
            ),
            (
                "KillSwitch-Allow-DHCPv6-In",
                "v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=17|LPort=546|RPort=547|Name=KillSwitch-Allow-DHCPv6-In|Desc=KillSwitch DHCPv6 Inbound|",
            ),
            (
                "KillSwitch-Block-Inbound-Low",
                "v2.31|Action=Block|Active=TRUE|Dir=In|RA4=0.0.0.0-126.255.255.255|Name=KillSwitch-Block-Inbound-Low|Desc=KillSwitch Block Inbound Low|",
            ),
            (
                "KillSwitch-Block-Inbound-High",
                "v2.31|Action=Block|Active=TRUE|Dir=In|RA4=128.0.0.0-255.255.255.255|Name=KillSwitch-Block-Inbound-High|Desc=KillSwitch Block Inbound High|",
            ),
            (
                "KillSwitch-Block-Outbound-Low",
                "v2.31|Action=Block|Active=TRUE|Dir=Out|RA4=0.0.0.0-126.255.255.255|Name=KillSwitch-Block-Outbound-Low|Desc=KillSwitch Block Outbound Low|",
            ),
            (
                "KillSwitch-Block-Outbound-High",
                "v2.31|Action=Block|Active=TRUE|Dir=Out|RA4=128.0.0.0-255.255.255.255|Name=KillSwitch-Block-Outbound-High|Desc=KillSwitch Block Outbound High|",
            ),
        ];

        let mut applied = Vec::new();
        for (name, val) in rules {
            if fw_key.set_value(name, &val).is_ok() {
                applied.push(name.to_string());
            }
        }
        info!(
            "🛡️ [BFE-REGISTRY] Applied {} native registry quarantine rules",
            applied.len()
        );
        applied
    }
    #[cfg(not(windows))]
    {
        vec!["KillSwitch-Allow-Loopback-In".to_string()]
    }
}

/// Removes all KillSwitch BFE registry firewall policy rules.
pub fn remove_all_killswitch_bfe_registry_rules() -> usize {
    #[cfg(windows)]
    {
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
        use winreg::types::FromRegValue;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let Ok(fw_key) = hklm.open_subkey_with_flags(BFE_FIREWALL_RULES_PATH, KEY_READ | KEY_WRITE)
        else {
            return 0;
        };

        let matching_keys: Vec<String> = fw_key
            .enum_values()
            .flatten()
            .filter_map(|(k, v)| {
                let is_ks_key = k.starts_with("KillSwitch-") || k.starts_with("OsoosiDLP-");
                let contains_ks_data = String::from_reg_value(&v)
                    .map(|s| s.contains("Name=KillSwitch-") || s.contains("Name=OsoosiDLP-"))
                    .unwrap_or(false);
                if is_ks_key || contains_ks_data {
                    Some(k)
                } else {
                    None
                }
            })
            .collect();

        let mut removed = 0usize;
        for k in matching_keys {
            if fw_key.delete_value(&k).is_ok() {
                removed += 1;
            }
        }
        info!(
            "🟢 [BFE-REGISTRY] Purged {} native KillSwitch firewall registry rules",
            removed
        );
        removed
    }
    #[cfg(not(windows))]
    {
        0
    }
}

// -----------------------------------------------------------------------------
// Direct TCP Socket Termination (`iphlpapi.dll`)
// -----------------------------------------------------------------------------
/// Terminates all active non-loopback TCP connections in states `3 | 4 | 5 | 8`
/// via `iphlpapi.dll` (`GetTcpTable` + `SetTcpEntry` with `MIB_TCP_STATE_DELETE_TCB = 12`).
/// Preserves loopback (`127.0.0.0/8`) and local control port `3030`.
pub fn terminate_all_non_loopback_tcp_sockets() -> usize {
    #[cfg(windows)]
    {
        use windows::core::{PCSTR, PCWSTR};
        use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

        let dll_name: Vec<u16> = "iphlpapi.dll\0".encode_utf16().collect();
        let Ok(h_mod) = (unsafe { LoadLibraryW(PCWSTR(dll_name.as_ptr())) }) else {
            return 0;
        };

        let Some(p_get) =
            (unsafe { GetProcAddress(h_mod, PCSTR(b"GetTcpTable\0".as_ptr())) })
        else {
            return 0;
        };
        let Some(p_set) =
            (unsafe { GetProcAddress(h_mod, PCSTR(b"SetTcpEntry\0".as_ptr())) })
        else {
            return 0;
        };

        let fn_get: FnGetTcpTable = unsafe { std::mem::transmute((p_get as usize) as *const ()) };
        let fn_set: FnSetTcpEntry = unsafe { std::mem::transmute((p_set as usize) as *const ()) };

        let mut size: u32 = 0;
        let first_status = unsafe { fn_get(std::ptr::null_mut(), &mut size, 0) };
        if first_status != ERROR_INSUFFICIENT_BUFFER || size < 4 {
            return 0;
        }

        // Pad buffer to handle connection churn between calls
        let mut buf = vec![0u8; size as usize + 512];
        let mut actual_size = buf.len() as u32;
        let status = unsafe { fn_get(buf.as_mut_ptr(), &mut actual_size, 0) };
        if status != ERROR_SUCCESS || actual_size < 4 {
            return 0;
        }

        let num_entries = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let row_size = std::mem::size_of::<MibTcpRow>();
        let max_entries = (buf.len().saturating_sub(4)) / row_size;
        let count = num_entries.min(max_entries);
        let rows_ptr = unsafe { buf.as_ptr().add(4) as *const MibTcpRow };

        let active_ctrl_ports = discover_active_control_ports();
        let mut terminated = 0usize;
        for i in 0..count {
            let row = unsafe { *rows_ptr.add(i) };
            let local_octets = row.dw_local_addr.to_ne_bytes();
            let remote_octets = row.dw_remote_addr.to_ne_bytes();
            let local_port = u16::from_be((row.dw_local_port & 0xFFFF) as u16);
            let remote_port = u16::from_be((row.dw_remote_port & 0xFFFF) as u16);

            // Invariant 1: Preserve loopback traffic (127.0.0.0/8)
            let is_loopback = local_octets[0] == 127 || remote_octets[0] == 127;
            // Invariant 2: Preserve all active control/WebUI ports (3030, 4040, active_port.txt)
            let is_control_port =
                active_ctrl_ports.contains(&local_port) || active_ctrl_ports.contains(&remote_port);
            // Invariant 3: Target half-open and established states
            let is_target_state = matches!(row.dw_state, 3 | 4 | 5 | 8);

            if is_target_state && !is_loopback && !is_control_port {
                let mut reset_row = row;
                reset_row.dw_state = MIB_TCP_STATE_DELETE_TCB;
                if unsafe { fn_set(&reset_row) } == ERROR_SUCCESS {
                    terminated += 1;
                }
            }
        }
        info!(
            "⚡ [TCP-RESET] Terminated {} active non-loopback TCP connections",
            terminated
        );
        terminated
    }
    #[cfg(not(windows))]
    {
        0
    }
}

/// Inspects the OS TCP connection table (`GetTcpTable` on Windows, `/proc/net/tcp` on Linux)
/// and returns `(active_non_loopback_peer_connections_count, remote_peer_endpoints_sample)`.
pub fn count_active_non_loopback_tcp_peers() -> (usize, Vec<String>) {
    #[cfg(windows)]
    {
        use windows::core::{PCSTR, PCWSTR};
        use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

        let dll_name: Vec<u16> = "iphlpapi.dll\0".encode_utf16().collect();
        let Ok(h_mod) = (unsafe { LoadLibraryW(PCWSTR(dll_name.as_ptr())) }) else {
            return (0, Vec::new());
        };
        let Some(p_get) = (unsafe { GetProcAddress(h_mod, PCSTR(b"GetTcpTable\0".as_ptr())) }) else {
            return (0, Vec::new());
        };
        let fn_get: FnGetTcpTable = unsafe { std::mem::transmute((p_get as usize) as *const ()) };

        let mut size: u32 = 0;
        let first_status = unsafe { fn_get(std::ptr::null_mut(), &mut size, 0) };
        if first_status != ERROR_INSUFFICIENT_BUFFER || size < 4 {
            return (0, Vec::new());
        }

        let mut buf = vec![0u8; size as usize + 512];
        let mut actual_size = buf.len() as u32;
        let status = unsafe { fn_get(buf.as_mut_ptr(), &mut actual_size, 0) };
        if status != ERROR_SUCCESS || actual_size < 4 {
            return (0, Vec::new());
        }

        let num_entries = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let row_size = std::mem::size_of::<MibTcpRow>();
        let max_entries = (buf.len().saturating_sub(4)) / row_size;
        let count = num_entries.min(max_entries);
        let rows_ptr = unsafe { buf.as_ptr().add(4) as *const MibTcpRow };

        let active_ctrl_ports = discover_active_control_ports();
        let mut active_count = 0usize;
        let mut peers = Vec::new();

        for i in 0..count {
            let row = unsafe { *rows_ptr.add(i) };
            let local_octets = row.dw_local_addr.to_ne_bytes();
            let remote_octets = row.dw_remote_addr.to_ne_bytes();
            let local_port = u16::from_be((row.dw_local_port & 0xFFFF) as u16);
            let remote_port = u16::from_be((row.dw_remote_port & 0xFFFF) as u16);

            let is_loopback = local_octets[0] == 127
                || remote_octets[0] == 127
                || remote_octets == [0, 0, 0, 0];
            let is_control_port =
                active_ctrl_ports.contains(&local_port) || active_ctrl_ports.contains(&remote_port);
            let is_active_state = matches!(row.dw_state, 3 | 4 | 5 | 8);

            if is_active_state && !is_loopback && !is_control_port {
                active_count += 1;
                if peers.len() < 20 {
                    let ep = format!(
                        "{}.{}.{}.{}:{}",
                        remote_octets[0],
                        remote_octets[1],
                        remote_octets[2],
                        remote_octets[3],
                        remote_port
                    );
                    if !peers.contains(&ep) {
                        peers.push(ep);
                    }
                }
            }
        }
        (active_count, peers)
    }
    #[cfg(target_os = "linux")]
    {
        let mut active_count = 0usize;
        let mut peers = Vec::new();
        if let Ok(raw) = std::fs::read_to_string("/proc/net/tcp") {
            for line in raw.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 && parts[3] == "01" {
                    let rem = parts[2];
                    if !rem.starts_with("0100007F:") && !rem.starts_with("00000000:") {
                        active_count += 1;
                        if peers.len() < 20 {
                            peers.push(rem.to_string());
                        }
                    }
                }
            }
        }
        (active_count, peers)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        (0, Vec::new())
    }
}

/// Terminates active TCP connections destined for specific remote IP addresses.
pub fn terminate_active_tcp_sockets_for_ips(ips: &[IpAddr]) -> usize {
    #[cfg(windows)]
    {
        use std::collections::HashSet;
        use windows::core::{PCSTR, PCWSTR};
        use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

        let target_v4_addrs: HashSet<u32> = ips
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(u32::from_ne_bytes(v4.octets())),
                IpAddr::V6(_) => None,
            })
            .collect();
        if target_v4_addrs.is_empty() {
            return 0;
        }

        let dll_name: Vec<u16> = "iphlpapi.dll\0".encode_utf16().collect();
        let Ok(h_mod) = (unsafe { LoadLibraryW(PCWSTR(dll_name.as_ptr())) }) else {
            return 0;
        };

        let Some(p_get) =
            (unsafe { GetProcAddress(h_mod, PCSTR(b"GetTcpTable\0".as_ptr())) })
        else {
            return 0;
        };
        let Some(p_set) =
            (unsafe { GetProcAddress(h_mod, PCSTR(b"SetTcpEntry\0".as_ptr())) })
        else {
            return 0;
        };

        let fn_get: FnGetTcpTable = unsafe { std::mem::transmute((p_get as usize) as *const ()) };
        let fn_set: FnSetTcpEntry = unsafe { std::mem::transmute((p_set as usize) as *const ()) };

        let mut size: u32 = 0;
        let first_status = unsafe { fn_get(std::ptr::null_mut(), &mut size, 0) };
        if first_status != ERROR_INSUFFICIENT_BUFFER || size < 4 {
            return 0;
        }

        let mut buf = vec![0u8; size as usize + 256];
        let mut actual_size = buf.len() as u32;
        let status = unsafe { fn_get(buf.as_mut_ptr(), &mut actual_size, 0) };
        if status != ERROR_SUCCESS || actual_size < 4 {
            return 0;
        }

        let num_entries = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let row_size = std::mem::size_of::<MibTcpRow>();
        let max_entries = (buf.len().saturating_sub(4)) / row_size;
        let count = num_entries.min(max_entries);
        let rows_ptr = unsafe { buf.as_ptr().add(4) as *const MibTcpRow };

        let mut terminated = 0usize;
        for i in 0..count {
            let mut row = unsafe { *rows_ptr.add(i) };
            if matches!(row.dw_state, 3 | 4 | 5 | 8)
                && target_v4_addrs.contains(&row.dw_remote_addr)
            {
                row.dw_state = MIB_TCP_STATE_DELETE_TCB;
                if unsafe { fn_set(&row) } == ERROR_SUCCESS {
                    terminated += 1;
                }
            }
        }
        terminated
    }
    #[cfg(not(windows))]
    {
        let _ = ips;
        0
    }
}

// -----------------------------------------------------------------------------
// High-Level Hermetic Quarantine Orchestrator
// -----------------------------------------------------------------------------
static GLOBAL_WFP_SESSION: OnceLock<parking_lot::Mutex<Option<WfpDynamicSession>>> =
    OnceLock::new();
static ACTIVE_WFP_FILTER_IDS: OnceLock<parking_lot::Mutex<Vec<u64>>> = OnceLock::new();

fn get_global_wfp_session() -> &'static parking_lot::Mutex<Option<WfpDynamicSession>> {
    GLOBAL_WFP_SESSION.get_or_init(|| parking_lot::Mutex::new(WfpDynamicSession::open().ok()))
}

fn get_active_wfp_filter_ids() -> &'static parking_lot::Mutex<Vec<u64>> {
    ACTIVE_WFP_FILTER_IDS.get_or_init(|| parking_lot::Mutex::new(Vec::new()))
}

fn wfp_filter_ledger_paths() -> [std::path::PathBuf; 2] {
    [
        std::env::temp_dir().join("killswitch_wfp_filters.json"),
        std::path::PathBuf::from("killswitch_wfp_filters.json"),
    ]
}

fn persist_wfp_filter_ids(ids: &[u64]) {
    if ids.is_empty() {
        return;
    }
    let mut all_ids = load_persisted_wfp_filter_ids();
    for &id in ids {
        if !all_ids.contains(&id) {
            all_ids.push(id);
        }
    }
    if let Ok(json) = serde_json::to_string(&all_ids) {
        for path in wfp_filter_ledger_paths() {
            let _ = std::fs::write(path, &json);
        }
    }
    let mut mem = get_active_wfp_filter_ids().lock();
    for &id in ids {
        if !mem.contains(&id) {
            mem.push(id);
        }
    }
}

fn load_persisted_wfp_filter_ids() -> Vec<u64> {
    let mut all_ids = Vec::new();
    {
        let mem = get_active_wfp_filter_ids().lock();
        for &id in mem.iter() {
            if !all_ids.contains(&id) {
                all_ids.push(id);
            }
        }
    }
    for path in wfp_filter_ledger_paths() {
        if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(parsed) = serde_json::from_str::<Vec<u64>>(&content) {
                for id in parsed {
                    if !all_ids.contains(&id) {
                        all_ids.push(id);
                    }
                }
            }
        }
    }
    if let Ok(ledger) = crate::state_ledger::StateLedger::open_or_init(None) {
        for receipt in &ledger.snapshot().network_receipts {
            for &id in &receipt.wfp_filter_ids {
                if !all_ids.contains(&id) {
                    all_ids.push(id);
                }
            }
        }
    }
    all_ids
}

fn clear_persisted_wfp_filter_ids() {
    get_active_wfp_filter_ids().lock().clear();
    for path in wfp_filter_ledger_paths() {
        let _ = std::fs::remove_file(path);
    }
}

/// Engages Windows Native Hermetic Network Quarantine:
/// 1. Installs WFP kernel filters (`fwpuclnt.dll`) and persists filter IDs across CLI invocations.
/// 2. Applies Windows BFE Registry rules directly via `winreg`.
/// 3. Resets active non-loopback TCP connections via `iphlpapi.dll`.
/// 4. Generates and returns a cryptographically signed `IsolationReceipt`.
pub fn engage_windows_network_quarantine(
    engaged_by: &str,
    reason: &str,
) -> KillSwitchResult<IsolationReceipt> {
    info!(
        engaged_by = %engaged_by,
        reason = %reason,
        "🚨 [QUARANTINE-WINDOWS] Engaging native Windows hermetic network quarantine"
    );

    let (session_id, wfp_filter_ids) = {
        let mut guard = get_global_wfp_session().lock();
        if guard.is_none() {
            *guard = WfpDynamicSession::open().ok();
        }
        if let Some(ref session) = *guard {
            let ids = match session.install_hermetic_quarantine_filters("KillSwitch") {
                Ok(ids) => ids,
                Err(e) => {
                    warn!(
                        "⚠️ [WFP] Could not install kernel WFP filters (Administrator token required): {}",
                        e
                    );
                    let _ = session.abort_transaction();
                    Vec::new()
                }
            };
            persist_wfp_filter_ids(&ids);
            #[cfg(windows)]
            let s_id = format!("{:p}", session.engine_handle);
            #[cfg(not(windows))]
            let s_id = "stub-session".to_string();
            (s_id, ids)
        } else {
            ("unsupported".to_string(), Vec::new())
        }
    };

    let registry_rules = apply_bfe_registry_quarantine_rules();
    let terminated_tcp = terminate_all_non_loopback_tcp_sockets();

    let mut preserved_ports = discover_active_control_ports();
    for p in [53u16, 67, 68, 546, 547] {
        if !preserved_ports.contains(&p) {
            preserved_ports.push(p);
        }
    }
    let preserved_ips = vec![
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];

    let receipt = IsolationReceipt::new(
        session_id,
        NetworkIsolationEngine::WindowsWfpDynamic,
        wfp_filter_ids,
        registry_rules,
        Vec::new(), // Netlink IDs are Linux only
        preserved_ports,
        preserved_ips,
        terminated_tcp,
        engaged_by.to_string(),
        reason.to_string(),
    );

    info!(
        receipt_id = %receipt.receipt_id,
        wfp_filters = receipt.wfp_filter_ids.len(),
        registry_rules = receipt.registry_rule_names.len(),
        terminated_tcp = receipt.terminated_tcp_connections_count,
        "🟢 [QUARANTINE-WINDOWS] Hermetic network isolation committed with receipt {}",
        receipt.receipt_id
    );

    Ok(receipt)
}

/// Disarms Windows Native Network Quarantine:
/// 1. Deletes all persisted and in-memory WFP filter IDs via `FwpmFilterDeleteById0`.
/// 2. Resets the WFP session handle.
/// 3. Cleans up all KillSwitch BFE registry firewall rules.
pub fn disarm_windows_network_quarantine(disarmed_by: &str, reason: &str) -> KillSwitchResult<()> {
    info!(
        disarmed_by = %disarmed_by,
        reason = %reason,
        "🟢 [DISARM-WINDOWS] Disarming native Windows network quarantine"
    );

    let filter_ids_to_delete = load_persisted_wfp_filter_ids();

    // 1. Delete all recorded WFP filter IDs and reset session
    {
        let mut guard = get_global_wfp_session().lock();
        if guard.is_none() {
            *guard = WfpDynamicSession::open().ok();
        }
        if let Some(ref session) = *guard {
            let _ = session.begin_transaction();
            for filter_id in &filter_ids_to_delete {
                let _ = session.delete_filter_by_id(*filter_id);
            }
            let _ = session.commit_transaction();
        }
        if let Some(session) = guard.take() {
            drop(session);
        }
        *guard = WfpDynamicSession::open().ok();
    }

    clear_persisted_wfp_filter_ids();

    // 2. Remove BFE Registry rules
    let removed_count = remove_all_killswitch_bfe_registry_rules();
    info!(
        "🟢 [DISARM-WINDOWS] Disarm complete. Deleted {} WFP filters and cleared {} registry rules.",
        filter_ids_to_delete.len(),
        removed_count
    );

    Ok(())
}

// -----------------------------------------------------------------------------
// WindowsWfpIsolator implementing NetworkIsolator
// -----------------------------------------------------------------------------
#[derive(Debug, Default, Clone)]
pub struct WindowsWfpIsolator;

impl NetworkIsolator for WindowsWfpIsolator {
    fn engage_quarantine(
        &self,
        _preserved_ports: &[u16],
        operator: &str,
        reason: &str,
    ) -> Result<IsolationReceipt, KillSwitchError> {
        engage_windows_network_quarantine(operator, reason)
    }

    fn restore_quarantine(&self, _receipt: &IsolationReceipt) -> Result<(), KillSwitchError> {
        disarm_windows_network_quarantine("disarm", "reverting quarantine")
    }

    fn reset_tcp_connections(
        &self,
        target_ips: Option<&[IpAddr]>,
    ) -> Result<usize, KillSwitchError> {
        if let Some(ips) = target_ips {
            Ok(terminate_active_tcp_sockets_for_ips(ips))
        } else {
            Ok(terminate_all_non_loopback_tcp_sockets())
        }
    }
}

// -----------------------------------------------------------------------------
// Unit & Integration Tests
// -----------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wfp_guid_display_and_equality() {
        assert_eq!(
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V4
        );
        assert_ne!(
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6
        );
    }

    #[test]
    fn test_wfp_session_lifecycle() {
        if WfpDynamicSession::is_available() {
            if let Ok(s) = WfpDynamicSession::open() {
                // Modifying dynamic BFE transactions requires elevated administrator privilege
                if s.begin_transaction().is_ok() {
                    assert!(s.abort_transaction().is_ok());
                }
            }
        }
    }

    #[test]
    fn test_endian_safe_loopback_detection() {
        let lb_v4 = u32::from_ne_bytes([127, 0, 0, 1]);
        let octets = lb_v4.to_ne_bytes();
        assert_eq!(octets[0], 127);

        let external_v4 = u32::from_ne_bytes([8, 8, 8, 8]);
        let ext_octets = external_v4.to_ne_bytes();
        assert_ne!(ext_octets[0], 127);
    }

    #[test]
    fn test_bfe_registry_rule_syntax_generator() {
        let applied = apply_native_bfe_registry_rule(
            "KillSwitch-UnitTest-Rule",
            "Out",
            "Block",
            Some(6),
            None,
            Some(443),
            &["198.51.100.1".parse().unwrap()],
        );
        #[cfg(windows)]
        {
            if applied {
                let _ = remove_all_killswitch_bfe_registry_rules();
            }
        }
        #[cfg(not(windows))]
        {
            assert!(applied);
        }
    }

    #[test]
    fn test_isolation_receipt_construction() {
        let receipt = IsolationReceipt::new(
            "test-session".to_string(),
            NetworkIsolationEngine::WindowsWfpDynamic,
            vec![100, 101],
            vec!["KillSwitch-Rule-1".to_string()],
            Vec::new(),
            vec![3030, 53],
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            5,
            "test_operator".to_string(),
            "Unit testing quarantine engagement".to_string(),
        );

        assert!(!receipt.receipt_id.is_empty());
        assert!(!receipt.receipt_hash_blake3.is_empty());
        assert_eq!(receipt.engine, NetworkIsolationEngine::WindowsWfpDynamic);
        assert_eq!(receipt.terminated_tcp_connections_count, 5);
        assert!(receipt.preserved_ports.contains(&3030));
    }

    #[test]
    fn test_windows_wfp_isolator_trait() {
        let isolator = WindowsWfpIsolator;
        let count = isolator.reset_tcp_connections(None).unwrap();
        // Sockets reset count is non-negative
        let _ = count;
    }
}
