//! # `killswitch-core`
//!
//! Native Zero-OS-Tool containment engine, process freeze, active tarpit,
//! 4-tier hybrid operator authentication, TPM 2.0 hardware sealing, and BLAKE3-chained state ledger.

pub mod auth;
pub mod fprime;
pub mod freeze;
pub mod killchain;
pub mod landlock;
pub mod pf;
pub mod service;
pub mod state_ledger;
pub mod tarpit;
pub mod tpm;
pub mod wfp;

pub use auth::{FrozenPidsProvider, OperatorAuthManager};
pub use fprime::{FPrimeDispatchResult, FPrimeOpcode, FPrimeSupervisor, FPrimeTopologyStatus};
pub use freeze::NativeProcessFreezer;
pub use killchain::{
    default_network_isolator, execute_host_disarm_unauthenticated, is_critical_system_pid,
    HostContainmentManager, KillChainHostManager, SimulatedNetworkIsolator,
};
pub use landlock::{
    apply_landlock_sandbox, get_active_non_loopback_connections, get_landlock_abi_version,
    parse_linux_ipv4_hex, parse_linux_ipv6_hex, parse_proc_net_content, parse_tcp_line,
    read_and_parse_proc_net_tcp, read_and_parse_proc_net_tcp6, LandlockSandboxConfig,
    LinuxNetlinkIsolator, LinuxSocketEntry, TcpState,
};
pub use pf::{
    generate_quarantine_rules, get_active_darwin_sockets, DarwinSocketEntry, MacOsPfIsolator,
    PfRuleSpec, DEFAULT_PF_ANCHOR, PF_DEVICE_PATH,
};
pub use service::{
    default_service_manager, generate_launchd_plist, generate_systemd_unit,
    LinuxServiceManager, MacOsServiceManager, NativeServiceManager,
};
#[cfg(target_os = "windows")]
pub use service::WindowsServiceManager;
pub use state_ledger::{StateLedger, StateLedgerSnapshot, GENESIS_HASH};
pub use tarpit::ActiveProcessTarpit;
pub use tpm::{
    probe_hardware_tpm, resolve_tpm_seal_path, seal_ledger_anchor, verify_tpm_and_ledger_anchor,
    HardwareTpmProbe, TpmSealedAnchorEnvelope, TpmStatusReport,
};
pub use wfp::{
    apply_bfe_registry_quarantine_rules, apply_native_bfe_registry_rule,
    disarm_windows_network_quarantine, engage_windows_network_quarantine,
    remove_all_killswitch_bfe_registry_rules, terminate_active_tcp_sockets_for_ips,
    terminate_all_non_loopback_tcp_sockets, WfpDynamicSession, WfpGuid, WindowsWfpIsolator,
};
