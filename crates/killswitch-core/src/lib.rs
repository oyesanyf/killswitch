//! # `killswitch-core`
//!
//! Native Zero-OS-Tool containment engine, process freeze, active tarpit,
//! 4-tier hybrid operator authentication, TPM 2.0 hardware sealing, and BLAKE3-chained state ledger.

pub mod agent_registry;
pub mod auth;
pub mod exec_sensor;
pub mod fprime;
pub mod freeze;
pub mod job_sandbox;
pub use job_sandbox as sandbox;
pub mod killchain;
pub mod landlock;
pub mod peer_pid;
pub mod pf;
pub mod service;
pub mod state_ledger;
pub mod tarpit;
pub mod tpm;
pub mod wfp;

#[cfg(target_os = "linux")]
pub use exec_sensor::LinuxProcessSensor;
#[cfg(target_os = "macos")]
pub use exec_sensor::MacOsProcessSensor;
#[cfg(target_os = "windows")]
pub use exec_sensor::WindowsProcessSensor;
pub use exec_sensor::{
    clear_exec_events, default_process_sensor, get_recent_exec_events, record_exec_event,
    register_exec_event_subscriber, simulate_exec_event, ExecEvent, ExecEventSubscriber,
    ExecSensorBuffer, NativeProcessSensor, SimulatedProcessSensor, EXEC_SENSOR_BUFFER,
    EXEC_SENSOR_DEFAULT_CAPACITY,
};

pub use peer_pid::resolve_loopback_peer_pid;

pub use agent_registry::{AgentLineageClass, SubtreeResolution, TrackedAgentRoot};
pub use auth::{FrozenPidsProvider, OperatorAuthManager};
pub use fprime::{FPrimeDispatchResult, FPrimeOpcode, FPrimeSupervisor, FPrimeTopologyStatus};
pub use freeze::NativeProcessFreezer;
#[cfg(target_os = "windows")]
pub use job_sandbox::WindowsAppContainerSandbox;
pub use job_sandbox::{
    enumerate_live_descendants, enumerate_process_subtree, format_windows_command_line,
    freeze_process_subtree, freeze_subtree_kernel, resume_process_subtree, spawn_confined_process,
    spawn_sandboxed_agent_process, ConfinedChild, JobSandboxConfig, SandboxedAgentConfig,
    SandboxedAgentProcess, SubtreeFreezeReport,
};
pub use killchain::{
    default_network_isolator, is_critical_system_pid, is_developer_or_agent_runtime,
    is_immutable_os_kernel_pid, HostContainmentManager, KillChainHostManager,
    SimulatedNetworkIsolator, TrackedAgentTreeRegistry,
};
pub use landlock::{
    apply_agent_seccomp_bpf, apply_landlock_sandbox, build_agent_seccomp_bpf,
    build_sock_destroy_msg, build_sock_destroy_msg_for_proto,
    generate_linux_nftables_quarantine_script, get_active_non_loopback_connections,
    get_active_non_loopback_udp_and_raw_sockets, get_landlock_abi_version,
    install_linux_nftables_quarantine, parse_linux_ipv4_hex, parse_linux_ipv6_hex,
    parse_proc_net_content, parse_tcp_line, read_and_parse_proc_net_raw,
    read_and_parse_proc_net_raw6, read_and_parse_proc_net_tcp, read_and_parse_proc_net_tcp6,
    read_and_parse_proc_net_udp, read_and_parse_proc_net_udp6, remove_linux_nftables_quarantine,
    LandlockSandboxConfig, LinuxNetlinkIsolator, LinuxSocketEntry, TcpState,
};
pub use pf::{
    generate_macos_seatbelt_profile, generate_quarantine_rules, get_active_darwin_sockets,
    DarwinSocketEntry, MacOsPfIsolator, PfRuleSpec, DEFAULT_PF_ANCHOR, PF_DEVICE_PATH,
};
#[cfg(target_os = "windows")]
pub use service::WindowsServiceManager;
pub use service::{
    default_service_manager, generate_launchd_plist, generate_systemd_unit, LinuxServiceManager,
    MacOsServiceManager, NativeServiceManager,
};
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
    FWPM_LAYER_IPFORWARD_V4, FWPM_LAYER_IPFORWARD_V6,
};

pub use killswitch_types::protocol::{
    OsiLayer, ProtocolDefinition, ProtocolDomain, ProtocolVectorType, UniversalProtocolCatalog,
    ALL_DOMAINS,
};
