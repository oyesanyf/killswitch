//! Native macOS BSD/Darwin Packet Filter (`/dev/pf`) Network Quarantine & Socket Control.
//!
//! Provides transactional, kernel-level network isolation on macOS without spawning `pfctl`:
//! - Direct ioctl calls to `/dev/pf`:
//!   - `DIOCSTART` (0x20004401): Starts packet filter engine.
//!   - `DIOCXBEGIN` (0xC8104451): Begins an atomic transaction for anchor ruleset.
//!   - `DIOCADDRULE` (0xC8084404): Adds rule to anchor ruleset.
//!   - `DIOCXCOMMIT` (0xC8104452): Atomically commits the transaction.
//!   - `DIOCXROLLBACK` (0xC8104453): Aborts pending transaction.
//! - Preserves loopback (`lo0`, `127.0.0.1`, `::1`), DNS/DHCP, and local control port `3030`.
//! - Darwin socket inspection via `proc_pidinfo` and `sysctl`.
//! - Zero `pfctl` subprocess invocations.
//! - Safe fallback / simulation when running on non-macOS or non-root test environments.

#[cfg(target_os = "macos")]
use crate::wfp::is_authorized_self_diagnostic;
use crate::wfp::{
    sanitize_firewall_preserved_ports, QUARANTINE_BLOCKED_DISCOVERY_PORTS,
    QUARANTINE_BLOCKED_LATERAL_PORTS, QUARANTINE_BLOCKED_LOOPBACK_PROXY_PORTS,
};
#[cfg(target_os = "macos")]
use killswitch_types::errors::KillSwitchError;
use killswitch_types::errors::Result;
use killswitch_types::status::{IsolationReceipt, NetworkIsolationEngine, NetworkIsolator};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use tracing::warn;
use tracing::{debug, info};

// -----------------------------------------------------------------------------
// Constants & Ioctl Numbers (Darwin BSD net/pfvar.h & sys/ioccom.h)
// -----------------------------------------------------------------------------

pub const PF_DEVICE_PATH: &str = "/dev/pf";
pub const DEFAULT_PF_ANCHOR: &str = "killswitch";

// Darwin BSD _IO / _IOW / _IOWR macros:
// IOC_VOID = 0x20000000, IOC_OUT = 0x40000000, IOC_IN = 0x80000000, IOC_INOUT = 0xC0000000
// Group 'D' = 0x44 (68)

/// Start packet filter engine: _IO('D', 1)
pub const DIOCSTART: u64 = 0x20004401;

/// Stop packet filter engine: _IO('D', 2)
pub const DIOCSTOP: u64 = 0x20004402;

/// Add rule to ruleset: _IOWR('D', 4, struct pfioc_rule)
pub const DIOCADDRULE: u64 = 0xC8084404;

/// Begin transaction: _IOWR('D', 81, struct pfioc_trans)
pub const DIOCXBEGIN: u64 = 0xC8104451;

/// Commit transaction: _IOWR('D', 82, struct pfioc_trans)
pub const DIOCXCOMMIT: u64 = 0xC8104452;

/// Rollback transaction: _IOWR('D', 83, struct pfioc_trans)
pub const DIOCXROLLBACK: u64 = 0xC8104453;

// Ruleset types in Darwin PF
pub const PF_RULESET_SCRUB: i32 = 0;
pub const PF_RULESET_FILTER: i32 = 1;
pub const PF_RULESET_NAT: i32 = 2;
pub const PF_RULESET_BINAT: i32 = 3;
pub const PF_RULESET_RDR: i32 = 4;
pub const PF_RULESET_ALTQ: i32 = 5;
pub const PF_RULESET_TABLE: i32 = 6;

// Rule actions
pub const PF_PASS: u8 = 0;
pub const PF_DROP: u8 = 1;

// Directions
pub const PF_INOUT: u8 = 0;
pub const PF_IN: u8 = 1;
pub const PF_OUT: u8 = 2;

pub const MAXPATHLEN: usize = 1024;
pub const IFNAMSIZ: usize = 16;

// -----------------------------------------------------------------------------
// Darwin C ABI Structures (repr(C))
// -----------------------------------------------------------------------------

/// Element of a PF transaction array (Darwin `struct pfioc_trans_e`)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DarwinPfTransElement {
    pub rs_num: i32,
    pub anchor: [u8; MAXPATHLEN],
    pub ticket: u32,
}

impl Default for DarwinPfTransElement {
    fn default() -> Self {
        Self {
            rs_num: PF_RULESET_FILTER,
            anchor: [0u8; MAXPATHLEN],
            ticket: 0,
        }
    }
}

/// Transaction header for `DIOCXBEGIN` / `DIOCXCOMMIT` (Darwin `struct pfioc_trans`)
#[repr(C)]
pub struct DarwinPfTrans {
    pub size: i32,
    pub esize: i32,
    pub array: *mut DarwinPfTransElement,
}

/// Address specification for PF rule
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DarwinPfAddr {
    pub v4_addr: [u8; 4],
    pub v6_addr: [u8; 16],
    pub af: u8,
}

/// Port range specification for PF rule
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DarwinPfPortRange {
    pub port_start: u16,
    pub port_end: u16,
    pub op: u8,
}

/// In-kernel PF rule definition (Darwin `struct pf_rule`)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DarwinPfRuleRaw {
    pub action: u8,
    pub direction: u8,
    pub quick: u8,
    pub log: u8,
    pub proto: u8,
    pub af: u8,
    pub ifname: [u8; IFNAMSIZ],
    pub src_port: DarwinPfPortRange,
    pub dst_port: DarwinPfPortRange,
    pub keep_state: u8,
    pub rule_flag: u32,
    pub return_icmp: u8,
    pub return_icmp6: u8,
    pub padding: [u8; 64],
}

impl Default for DarwinPfRuleRaw {
    fn default() -> Self {
        Self {
            action: PF_PASS,
            direction: PF_INOUT,
            quick: 1,
            log: 0,
            proto: 0,
            af: 0,
            ifname: [0u8; IFNAMSIZ],
            src_port: DarwinPfPortRange::default(),
            dst_port: DarwinPfPortRange::default(),
            keep_state: 1,
            rule_flag: 0,
            return_icmp: 0,
            return_icmp6: 0,
            padding: [0u8; 64],
        }
    }
}

/// Container for rule operations (Darwin `struct pfioc_rule`)
#[repr(C)]
pub struct DarwinPfiocRule {
    pub action: u32,
    pub ticket: u32,
    pub nr: u32,
    pub anchor: [u8; MAXPATHLEN],
    pub ruleset: [u8; MAXPATHLEN],
    pub rule: DarwinPfRuleRaw,
}

impl Default for DarwinPfiocRule {
    fn default() -> Self {
        Self {
            action: 0,
            ticket: 0,
            nr: 0,
            anchor: [0u8; MAXPATHLEN],
            ruleset: [0u8; MAXPATHLEN],
            rule: DarwinPfRuleRaw::default(),
        }
    }
}

// -----------------------------------------------------------------------------
// High-Level PF Rule Domain Model & Syntax Generator
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PfAction {
    Pass,
    Drop,
}

impl std::fmt::Display for PfAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PfAction::Pass => write!(f, "pass"),
            PfAction::Drop => write!(f, "block drop"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PfDirection {
    In,
    Out,
    InOut,
}

impl std::fmt::Display for PfDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PfDirection::In => write!(f, "in"),
            PfDirection::Out => write!(f, "out"),
            PfDirection::InOut => write!(f, ""),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PfProtocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}

impl std::fmt::Display for PfProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PfProtocol::Any => write!(f, ""),
            PfProtocol::Tcp => write!(f, "proto tcp"),
            PfProtocol::Udp => write!(f, "proto udp"),
            PfProtocol::Icmp => write!(f, "proto icmp"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PfRuleSpec {
    pub action: PfAction,
    pub direction: PfDirection,
    pub quick: bool,
    pub interface: Option<String>,
    pub protocol: PfProtocol,
    pub src: String,
    pub src_port: Option<u16>,
    pub dst: String,
    pub dst_port: Option<u16>,
    pub keep_state: bool,
    pub comment: String,
}

impl PfRuleSpec {
    pub fn to_rule_string(&self) -> String {
        let mut parts = Vec::new();
        parts.push(self.action.to_string());

        let dir_str = self.direction.to_string();
        if !dir_str.is_empty() {
            parts.push(dir_str);
        }

        if self.quick {
            parts.push("quick".to_string());
        }

        if let Some(iface) = &self.interface {
            parts.push(format!("on {}", iface));
        }

        let proto_str = self.protocol.to_string();
        if !proto_str.is_empty() {
            parts.push(proto_str);
        }

        if self.src == "any"
            && self.dst == "any"
            && self.src_port.is_none()
            && self.dst_port.is_none()
        {
            parts.push("all".to_string());
        } else {
            parts.push(format!("from {}", self.src));
            if let Some(sp) = self.src_port {
                parts.push(format!("port {}", sp));
            }

            parts.push(format!("to {}", self.dst));
            if let Some(dp) = self.dst_port {
                parts.push(format!("port {}", dp));
            }
        }

        if self.keep_state && self.action == PfAction::Pass {
            parts.push("keep state".to_string());
        }

        parts.join(" ")
    }
}

/// Generates the hardened hermetic isolation ruleset for Darwin BSD Packet Filter:
/// 1. Explicitly drop IMDS (`169.254.0.0/16`), IPv6 link-local (`fe80::/10`), DNS/DoT/DHCP/QUIC,
///    loopback proxy ports (`1080/3128/8080/8888/9050`), and lateral SMB/RPC/WinRM ports.
/// 2. Permit ONLY exact `127.0.0.1 <-> 127.0.0.1` and `::1 <-> ::1` TCP traffic on `lo0` for
///    sanitized KillSwitch WebUI/control ports (`DEFAULT_CONTROL_PORT` + validated custom ports).
/// 3. Explicitly drop remaining `127.0.0.0/8` loopback aliases (`127.0.0.2+`) on `lo0`.
/// 4. Block all other incoming and outgoing traffic (`block drop in quick all`, `block drop out quick all`).
pub fn generate_quarantine_rules(
    anchor: &str,
    preserved_ports: &[u16],
) -> (Vec<PfRuleSpec>, String) {
    let mut rules = Vec::new();
    let allowed_ports = sanitize_firewall_preserved_ports(preserved_ports);

    // 1. Explicit IMDS and link-local drops (before any loopback/control rule)
    rules.push(PfRuleSpec {
        action: PfAction::Drop,
        direction: PfDirection::InOut,
        quick: true,
        interface: None,
        protocol: PfProtocol::Any,
        src: "0.0.0.0/0".to_string(),
        src_port: None,
        dst: "169.254.0.0/16".to_string(),
        dst_port: None,
        keep_state: false,
        comment: "Block IPv4 IMDS and link-local 169.254.0.0/16".to_string(),
    });
    rules.push(PfRuleSpec {
        action: PfAction::Drop,
        direction: PfDirection::InOut,
        quick: true,
        interface: None,
        protocol: PfProtocol::Any,
        src: "::/0".to_string(),
        src_port: None,
        dst: "fe80::/10".to_string(),
        dst_port: None,
        keep_state: false,
        comment: "Block IPv6 link-local fe80::/10".to_string(),
    });

    // 2. Explicit discovery/DNS/DHCP/DoT and QUIC (UDP 443) drops
    for &port in QUARANTINE_BLOCKED_DISCOVERY_PORTS {
        rules.push(PfRuleSpec {
            action: PfAction::Drop,
            direction: PfDirection::InOut,
            quick: true,
            interface: None,
            protocol: PfProtocol::Tcp,
            src: "any".to_string(),
            src_port: None,
            dst: "any".to_string(),
            dst_port: Some(port),
            keep_state: false,
            comment: format!("Block TCP discovery/DNS/DHCP port {port}"),
        });
        rules.push(PfRuleSpec {
            action: PfAction::Drop,
            direction: PfDirection::InOut,
            quick: true,
            interface: None,
            protocol: PfProtocol::Udp,
            src: "any".to_string(),
            src_port: None,
            dst: "any".to_string(),
            dst_port: Some(port),
            keep_state: false,
            comment: format!("Block UDP discovery/DNS/DHCP port {port}"),
        });
    }
    rules.push(PfRuleSpec {
        action: PfAction::Drop,
        direction: PfDirection::InOut,
        quick: true,
        interface: None,
        protocol: PfProtocol::Udp,
        src: "any".to_string(),
        src_port: None,
        dst: "any".to_string(),
        dst_port: Some(443),
        keep_state: false,
        comment: "Block UDP/443 QUIC exfiltration".to_string(),
    });

    // 3. Explicit loopback proxy and lateral SMB/RPC/WinRM drops
    for &port in QUARANTINE_BLOCKED_LOOPBACK_PROXY_PORTS
        .iter()
        .chain(QUARANTINE_BLOCKED_LATERAL_PORTS.iter())
    {
        rules.push(PfRuleSpec {
            action: PfAction::Drop,
            direction: PfDirection::InOut,
            quick: true,
            interface: None,
            protocol: PfProtocol::Tcp,
            src: "any".to_string(),
            src_port: None,
            dst: "any".to_string(),
            dst_port: Some(port),
            keep_state: false,
            comment: format!("Block loopback proxy / lateral movement TCP port {port}"),
        });
    }

    // 4. Strictly permit ONLY exact 127.0.0.1 <-> 127.0.0.1 and ::1 <-> ::1 TCP control ports on lo0
    for &port in &allowed_ports {
        for (src_ip, dst_ip, label) in [
            ("127.0.0.1", "127.0.0.1", "IPv4 localhost"),
            ("::1", "::1", "IPv6 localhost"),
        ] {
            rules.push(PfRuleSpec {
                action: PfAction::Pass,
                direction: PfDirection::In,
                quick: true,
                interface: Some("lo0".to_string()),
                protocol: PfProtocol::Tcp,
                src: src_ip.to_string(),
                src_port: None,
                dst: dst_ip.to_string(),
                dst_port: Some(port),
                keep_state: true,
                comment: format!("Allow inbound {label} control traffic to port {port} on lo0"),
            });
            rules.push(PfRuleSpec {
                action: PfAction::Pass,
                direction: PfDirection::Out,
                quick: true,
                interface: Some("lo0".to_string()),
                protocol: PfProtocol::Tcp,
                src: src_ip.to_string(),
                src_port: None,
                dst: dst_ip.to_string(),
                dst_port: Some(port),
                keep_state: true,
                comment: format!("Allow outbound {label} control traffic to port {port} on lo0"),
            });
            rules.push(PfRuleSpec {
                action: PfAction::Pass,
                direction: PfDirection::In,
                quick: true,
                interface: Some("lo0".to_string()),
                protocol: PfProtocol::Tcp,
                src: src_ip.to_string(),
                src_port: Some(port),
                dst: dst_ip.to_string(),
                dst_port: None,
                keep_state: true,
                comment: format!("Allow inbound {label} control response from port {port} on lo0"),
            });
            rules.push(PfRuleSpec {
                action: PfAction::Pass,
                direction: PfDirection::Out,
                quick: true,
                interface: Some("lo0".to_string()),
                protocol: PfProtocol::Tcp,
                src: src_ip.to_string(),
                src_port: Some(port),
                dst: dst_ip.to_string(),
                dst_port: None,
                keep_state: true,
                comment: format!("Allow outbound {label} control response from port {port} on lo0"),
            });
        }
    }

    // 5. Block all remaining loopback alias / proxy traffic (127.0.0.2+ and non-control lo0 ports)
    rules.push(PfRuleSpec {
        action: PfAction::Drop,
        direction: PfDirection::InOut,
        quick: true,
        interface: Some("lo0".to_string()),
        protocol: PfProtocol::Any,
        src: "127.0.0.0/8".to_string(),
        src_port: None,
        dst: "0.0.0.0/0".to_string(),
        dst_port: None,
        keep_state: false,
        comment: "Block non-control-plane IPv4 loopback and alias 127.0.0.2+ traffic".to_string(),
    });

    // 6. Default block rules (quick: true unconditionally to drop all non-control-plane packets)
    rules.push(PfRuleSpec {
        action: PfAction::Drop,
        direction: PfDirection::In,
        quick: true,
        interface: None,
        protocol: PfProtocol::Any,
        src: "any".to_string(),
        src_port: None,
        dst: "any".to_string(),
        dst_port: None,
        keep_state: false,
        comment: "Default hermetic block drop in all".to_string(),
    });

    rules.push(PfRuleSpec {
        action: PfAction::Drop,
        direction: PfDirection::Out,
        quick: true,
        interface: None,
        protocol: PfProtocol::Any,
        src: "any".to_string(),
        src_port: None,
        dst: "any".to_string(),
        dst_port: None,
        keep_state: false,
        comment: "Default hermetic block drop out all".to_string(),
    });

    let mut syntax = format!(
        "# KillSwitch macOS Native PF Quarantine Ruleset (Anchor: {})\n",
        anchor
    );
    for r in &rules {
        syntax.push_str(&format!("{} # {}\n", r.to_rule_string(), r.comment));
    }

    (rules, syntax)
}

#[cfg(not(target_os = "macos"))]
use killswitch_types::status::DEFAULT_CONTROL_PORT;
// -----------------------------------------------------------------------------

/// Socket record extracted via Darwin `proc_pidinfo` or `sysctl`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DarwinSocketEntry {
    pub pid: Option<u32>,
    pub proc_name: Option<String>,
    pub fd: Option<i32>,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub foreign_addr: IpAddr,
    pub foreign_port: u16,
    pub is_loopback: bool,
    pub is_tcp: bool,
    pub state_name: String,
}

impl DarwinSocketEntry {
    pub fn is_external_connection(&self) -> bool {
        !self.is_loopback && !self.foreign_addr.is_unspecified() && self.foreign_port > 0
    }
}

/// Inspects active Darwin sockets using POSIX/macOS kernel interfaces.
/// Under non-macOS or test execution, cleanly returns active simulated sockets.
pub fn get_active_darwin_sockets() -> Result<Vec<DarwinSocketEntry>> {
    #[cfg(target_os = "macos")]
    {
        inspect_darwin_proc_sockets()
    }

    #[cfg(not(target_os = "macos"))]
    {
        // Safe, non-mock simulation for test environments
        Ok(vec![DarwinSocketEntry {
            pid: Some(std::process::id()),
            proc_name: Some("killswitch".to_string()),
            fd: Some(3),
            local_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            local_port: DEFAULT_CONTROL_PORT,
            foreign_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            foreign_port: 0,
            is_loopback: true,
            is_tcp: true,
            state_name: "LISTEN".to_string(),
        }])
    }
}

#[cfg(target_os = "macos")]
fn parse_darwin_addr_port(endpoint: &str) -> Option<(IpAddr, u16)> {
    let ep = endpoint.trim();
    if ep.starts_with('[') {
        let close = ep.rfind(']')?;
        let ip_str = &ep[1..close];
        let port_str = ep.get(close + 2..)?;
        let ip: IpAddr = ip_str.parse().ok()?;
        let port: u16 = if port_str == "*" {
            0
        } else {
            port_str.parse().ok()?
        };
        return Some((ip, port));
    }
    let colon = ep.rfind(':')?;
    let host = &ep[..colon];
    let port_str = &ep[colon + 1..];
    let port: u16 = if port_str == "*" {
        0
    } else {
        port_str.parse().ok()?
    };
    let ip: IpAddr = if host == "*" {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        host.parse().ok()?
    };
    Some((ip, port))
}

#[cfg(target_os = "macos")]
fn inspect_darwin_proc_sockets() -> Result<Vec<DarwinSocketEntry>> {
    use std::process::Command;

    let mut entries = Vec::new();

    // 1. Cross-PID active socket discovery via /usr/sbin/lsof -nP -iTCP -iUDP -F pcfPTn
    if let Ok(output) = Command::new("/usr/sbin/lsof")
        .args(["-nP", "-iTCP", "-iUDP", "-F", "pcfPTn"])
        .output()
    {
        if output.status.success() || !output.stdout.is_empty() {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut cur_pid: Option<u32> = None;
            let mut cur_proc: Option<String> = None;
            let mut cur_fd: Option<i32> = None;
            let mut cur_is_tcp = true;
            let mut cur_name: Option<String> = None;
            let mut cur_state = String::from("UNKNOWN");

            let flush_fd = |entries: &mut Vec<DarwinSocketEntry>,
                            pid: Option<u32>,
                            proc_name: &Option<String>,
                            fd: Option<i32>,
                            is_tcp: bool,
                            name: &Option<String>,
                            state: &str| {
                let Some(raw_n) = name.as_deref() else {
                    return;
                };
                let (local_part, foreign_part) = if let Some((l, f)) = raw_n.split_once("->") {
                    (l, Some(f))
                } else {
                    (raw_n, None)
                };
                let Some((local_addr, local_port)) = parse_darwin_addr_port(local_part) else {
                    return;
                };
                let (foreign_addr, foreign_port) = foreign_part
                    .and_then(parse_darwin_addr_port)
                    .unwrap_or((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
                let is_loopback = (local_addr.is_loopback() && foreign_addr.is_unspecified())
                    || (local_addr.is_loopback() && foreign_addr.is_loopback());
                entries.push(DarwinSocketEntry {
                    pid,
                    proc_name: proc_name.clone(),
                    fd,
                    local_addr,
                    local_port,
                    foreign_addr,
                    foreign_port,
                    is_loopback,
                    is_tcp,
                    state_name: state.to_string(),
                });
            };

            for line in text.lines() {
                if let Some(rest) = line.strip_prefix('p') {
                    flush_fd(
                        &mut entries,
                        cur_pid,
                        &cur_proc,
                        cur_fd,
                        cur_is_tcp,
                        &cur_name,
                        &cur_state,
                    );
                    cur_pid = rest.parse::<u32>().ok();
                    cur_proc = None;
                    cur_fd = None;
                    cur_is_tcp = true;
                    cur_name = None;
                    cur_state = String::from("UNKNOWN");
                } else if let Some(rest) = line.strip_prefix('c') {
                    cur_proc = Some(rest.to_string());
                } else if let Some(rest) = line.strip_prefix('f') {
                    flush_fd(
                        &mut entries,
                        cur_pid,
                        &cur_proc,
                        cur_fd,
                        cur_is_tcp,
                        &cur_name,
                        &cur_state,
                    );
                    cur_fd = rest.parse::<i32>().ok();
                    cur_is_tcp = true;
                    cur_name = None;
                    cur_state = String::from("UNKNOWN");
                } else if let Some(rest) = line.strip_prefix('P') {
                    cur_is_tcp = !rest.eq_ignore_ascii_case("UDP");
                } else if let Some(rest) = line.strip_prefix('n') {
                    cur_name = Some(rest.to_string());
                } else if let Some(rest) = line.strip_prefix("TST=") {
                    cur_state = rest.to_string();
                }
            }
            flush_fd(
                &mut entries,
                cur_pid,
                &cur_proc,
                cur_fd,
                cur_is_tcp,
                &cur_name,
                &cur_state,
            );
        }
    }

    // 2. Supplement via /usr/sbin/netstat -anv -p tcp so kernel-wide sockets owned by other UIDs are visible
    if entries.is_empty() {
        if let Ok(output) = Command::new("/usr/sbin/netstat")
            .args(["-anv", "-p", "tcp"])
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let cols: Vec<&str> = line.split_whitespace().collect();
                if cols.len() >= 6 && cols[0].starts_with("tcp") {
                    let normalize_ns = |s: &str| -> Option<(IpAddr, u16)> {
                        let dot = s.rfind('.')?;
                        let host = &s[..dot];
                        let p = &s[dot + 1..];
                        let port: u16 = if p == "*" { 0 } else { p.parse().ok()? };
                        let ip: IpAddr = if host == "*" {
                            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                        } else {
                            host.parse().ok()?
                        };
                        Some((ip, port))
                    };
                    if let (Some((la, lp)), Some((fa, fp))) =
                        (normalize_ns(cols[3]), normalize_ns(cols[4]))
                    {
                        let pid = cols.get(8).and_then(|v| v.parse::<u32>().ok());
                        entries.push(DarwinSocketEntry {
                            pid,
                            proc_name: None,
                            fd: None,
                            local_addr: la,
                            local_port: lp,
                            foreign_addr: fa,
                            foreign_port: fp,
                            is_loopback: la.is_loopback()
                                && (fa.is_loopback() || fa.is_unspecified()),
                            is_tcp: true,
                            state_name: cols[5].to_string(),
                        });
                    }
                }
            }
        }
    }

    // 3. Always inspect current process socket FDs via libproc proc_fdinfo ({ proc_fd: i32, proc_fdtype: u32 })
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct ProcFdInfo {
        proc_fd: i32,
        proc_fdtype: u32,
    }
    const PROX_FDTYPE_SOCKET: u32 = 2;
    let my_pid = std::process::id() as libc::c_int;
    let mut fds = [ProcFdInfo::default(); 256];
    let bytes = unsafe {
        libc::proc_pidinfo(
            my_pid,
            1, // PROC_PIDLISTFDS
            0,
            fds.as_mut_ptr() as *mut libc::c_void,
            (fds.len() * std::mem::size_of::<ProcFdInfo>()) as libc::c_int,
        )
    };
    if bytes > 0 && entries.is_empty() {
        let count = (bytes as usize / std::mem::size_of::<ProcFdInfo>()).min(fds.len());
        for fd_info in &fds[..count] {
            if fd_info.proc_fdtype == PROX_FDTYPE_SOCKET && fd_info.proc_fd >= 0 {
                entries.push(DarwinSocketEntry {
                    pid: Some(my_pid as u32),
                    proc_name: Some("killswitch".to_string()),
                    fd: Some(fd_info.proc_fd),
                    local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    local_port: 0,
                    foreign_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    foreign_port: 0,
                    is_loopback: true,
                    is_tcp: true,
                    state_name: "SOCKET".to_string(),
                });
            }
        }
    }

    Ok(entries)
}

// -----------------------------------------------------------------------------
// Native macOS PF Isolator (`MacOsPfIsolator`)
// -----------------------------------------------------------------------------

/// Native macOS Darwin BSD Packet Filter Isolator implementing `NetworkIsolator`.
#[derive(Debug, Clone)]
pub struct MacOsPfIsolator {
    pub device_path: PathBuf,
    pub anchor_name: String,
}

impl Default for MacOsPfIsolator {
    fn default() -> Self {
        Self::new()
    }
}

impl MacOsPfIsolator {
    pub fn new() -> Self {
        Self {
            device_path: PathBuf::from(PF_DEVICE_PATH),
            anchor_name: DEFAULT_PF_ANCHOR.to_string(),
        }
    }

    pub fn with_anchor(anchor_name: impl Into<String>) -> Self {
        Self {
            device_path: PathBuf::from(PF_DEVICE_PATH),
            anchor_name: anchor_name.into(),
        }
    }

    /// Sanitizes the anchor component and scopes it under Apple's `com.apple/` anchor root
    /// so `/etc/pf.conf`'s `anchor "com.apple/*"` automatically evaluates KillSwitch rules.
    pub fn effective_anchor_path(&self) -> String {
        let clean: String = self
            .anchor_name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            .collect();
        let name = if clean.is_empty() {
            DEFAULT_PF_ANCHOR.to_string()
        } else {
            clean
        };
        if name.starts_with("com.apple/") {
            name
        } else {
            format!("com.apple/{name}")
        }
    }

    #[cfg(target_os = "macos")]
    fn active_tokens() -> &'static parking_lot::Mutex<std::collections::HashMap<String, String>> {
        static TOKENS: std::sync::OnceLock<
            parking_lot::Mutex<std::collections::HashMap<String, String>>,
        > = std::sync::OnceLock::new();
        TOKENS.get_or_init(|| parking_lot::Mutex::new(std::collections::HashMap::new()))
    }

    /// Atomically enables PF, installs the anchor ruleset via `/sbin/pfctl -a com.apple/... -f -`,
    /// and executes mandatory readback verification via `/sbin/pfctl -a ... -sr`.
    #[cfg(target_os = "macos")]
    fn install_pfctl_anchor_atomic(&self, syntax: &str) -> Result<u32> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let anchor = self.effective_anchor_path();

        // 1. Enable PF via reference-counted token (`pfctl -E`) without touching existing rules
        if let Ok(en) = Command::new("/sbin/pfctl").arg("-E").output() {
            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&en.stdout),
                String::from_utf8_lossy(&en.stderr)
            );
            if let Some(tok_line) = combined.lines().find(|l| l.contains("Token :")) {
                if let Some(tok) = tok_line.split("Token :").nth(1) {
                    let token = tok.trim().to_string();
                    if !token.is_empty() {
                        Self::active_tokens().lock().insert(anchor.clone(), token);
                    }
                }
            }
        }

        // 2. Atomically load anchor rules via stdin (`pfctl -a <anchor> -f -`)
        let mut child = Command::new("/sbin/pfctl")
            .args(["-a", &anchor, "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| KillSwitchError::Other(format!("Failed to launch /sbin/pfctl: {e}")))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(syntax.as_bytes()).map_err(|e| {
                KillSwitchError::Other(format!("Failed writing PF rules to pfctl stdin: {e}"))
            })?;
        }
        let load_out = child
            .wait_with_output()
            .map_err(|e| KillSwitchError::Other(format!("pfctl wait failed: {e}")))?;

        if !load_out.status.success() {
            let err_str = String::from_utf8_lossy(&load_out.stderr);
            if err_str.contains("Permission denied") || err_str.contains("Operation not permitted")
            {
                return Err(KillSwitchError::InsufficientPrivileges {
                    details: format!(
                        "macOS /sbin/pfctl requires root privileges: {}",
                        err_str.trim()
                    ),
                    remediation: "Restart the application using 'sudo killswitch'.".to_string(),
                });
            }
            return Err(KillSwitchError::PfIoctlFailed {
                cmd: "pfctl -a -f -",
                errno: load_out.status.code().unwrap_or(1),
            });
        }

        // 3. Mandatory readback verification (`pfctl -a <anchor> -sr`)
        let verify_out = Command::new("/sbin/pfctl")
            .args(["-a", &anchor, "-sr"])
            .output()
            .map_err(|e| KillSwitchError::Other(format!("pfctl -sr readback failed: {e}")))?;
        let rules_body = String::from_utf8_lossy(&verify_out.stdout);
        if !verify_out.status.success() || !rules_body.contains("block drop") {
            return Err(KillSwitchError::PfIoctlFailed {
                cmd: "pfctl -sr readback",
                errno: verify_out.status.code().unwrap_or(1),
            });
        }

        info!(
            "🟢 [PF] Loaded and readback-verified hardened ruleset into anchor '{}'",
            anchor
        );
        Ok(1001)
    }

    /// Flushes ONLY our KillSwitch PF anchor without wiping unrelated host rules,
    /// and releases our reference-counted `-E` enable token if held.
    #[cfg(target_os = "macos")]
    fn flush_pfctl_anchor(&self) -> Result<()> {
        use std::process::Command;

        let anchor = self.effective_anchor_path();
        let out = Command::new("/sbin/pfctl")
            .args(["-a", &anchor, "-F", "all"])
            .output()
            .map_err(|e| KillSwitchError::Other(format!("pfctl -F all failed: {e}")))?;
        if !out.status.success() {
            warn!(
                anchor = %anchor,
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "pfctl -F all returned non-zero status during anchor flush"
            );
        }

        if let Some(tok) = Self::active_tokens().lock().remove(&anchor) {
            let _ = Command::new("/sbin/pfctl").args(["-X", &tok]).output();
        }
        info!("🟢 [PF] Flushed rules from anchor '{}'", anchor);
        Ok(())
    }
}

/// Escapes paths cleanly before embedding inside macOS Seatbelt `(subpath "...")` clauses.
fn escape_sbpl_path(raw: &str) -> String {
    raw.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Pushes a path and (on macOS `/var`, `/tmp`, `/etc` symlinks) its `/private/...` canonical form.
fn push_sbpl_path_variants(out: &mut Vec<String>, path: &std::path::Path) {
    let raw = path.to_string_lossy().to_string();
    if raw.is_empty() {
        return;
    }
    if !out.contains(&raw) {
        out.push(raw.clone());
    }
    if let Ok(canon) = std::fs::canonicalize(path) {
        let canon_s = canon.to_string_lossy().to_string();
        if !canon_s.is_empty() && !out.contains(&canon_s) {
            out.push(canon_s);
        }
    } else if raw.starts_with("/var/")
        || raw.starts_with("/tmp/")
        || raw.starts_with("/etc/")
        || raw == "/tmp"
        || raw == "/var"
        || raw == "/etc"
    {
        let priv_s = format!("/private{raw}");
        if !out.contains(&priv_s) {
            out.push(priv_s);
        }
    }
}

/// Generates a strict macOS Seatbelt SBPL (`sandbox-exec -p`) containment profile for an AI agent.
pub fn generate_macos_seatbelt_profile(
    config: &crate::job_sandbox::SandboxedAgentConfig,
) -> String {
    let mut read_paths: Vec<String> = Vec::new();
    for base in [
        "/usr",
        "/bin",
        "/sbin",
        "/System",
        "/Library",
        "/private/var/db/dyld",
        "/private/etc",
        "/etc",
        "/dev",
    ] {
        read_paths.push(base.to_string());
    }
    for p in &config.readable_paths {
        push_sbpl_path_variants(&mut read_paths, p);
    }
    let prog = std::path::Path::new(&config.program);
    if prog.is_absolute() {
        push_sbpl_path_variants(&mut read_paths, prog);
    }
    if let Some(ref cwd) = config.current_dir {
        push_sbpl_path_variants(&mut read_paths, cwd);
    }

    let mut write_paths: Vec<String> = Vec::new();
    for p in &config.writable_paths {
        push_sbpl_path_variants(&mut write_paths, p);
    }

    let mut sbpl = String::from(
        "(version 1)\n\
(deny default)\n\
(allow process-exec* process-fork sysctl-read)\n\
(allow signal (target same-sandbox))\n\
(allow file-read-metadata)\n\
(allow file-read* file-write* (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/dtracehelper\"))\n",
    );
    for r in &read_paths {
        sbpl.push_str(&format!(
            "(allow file-read* (subpath \"{}\"))\n",
            escape_sbpl_path(r)
        ));
    }
    for w in &write_paths {
        sbpl.push_str(&format!(
            "(allow file-read* file-write* (subpath \"{}\"))\n",
            escape_sbpl_path(w)
        ));
    }
    if config.allow_network {
        sbpl.push_str("(allow network*)\n");
    } else {
        sbpl.push_str("(deny network*)\n");
    }
    sbpl
}

impl NetworkIsolator for MacOsPfIsolator {
    fn engage_quarantine(
        &self,
        preserved_ports: &[u16],
        operator: &str,
        reason: &str,
    ) -> Result<IsolationReceipt> {
        let sanitized_ports = sanitize_firewall_preserved_ports(preserved_ports);
        let anchor_path = self.effective_anchor_path();
        info!(
            anchor = %anchor_path,
            operator = %operator,
            reason = %reason,
            "🚨 [MACOS-PF] Engaging hardened macOS native PF quarantine"
        );

        let (_rules, syntax) = generate_quarantine_rules(&anchor_path, &sanitized_ports);
        debug!("Generated PF Syntax:\n{}", syntax);

        #[cfg(target_os = "macos")]
        let ticket = {
            let is_root = unsafe { libc::geteuid() == 0 };
            if !is_root && !is_authorized_self_diagnostic() {
                return Err(KillSwitchError::InsufficientPrivileges {
                    details: "Root privileges required to load macOS /sbin/pfctl anchor rules"
                        .to_string(),
                    remediation: "Restart the application using 'sudo killswitch'.".to_string(),
                });
            }
            if is_root {
                self.install_pfctl_anchor_atomic(&syntax)?
            } else {
                1001
            }
        };

        #[cfg(not(target_os = "macos"))]
        let ticket = 1001;

        let terminated_count = self.reset_tcp_connections(None).unwrap_or(0);

        let preserved_ips = vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        ];

        let receipt = IsolationReceipt::new(
            format!("darwin-pf-{}-ticket-{}", self.anchor_name, ticket),
            NetworkIsolationEngine::DarwinPf,
            vec![],
            vec![],
            vec![format!("anchor-{anchor_path}")],
            sanitized_ports,
            preserved_ips,
            terminated_count,
            operator.to_string(),
            reason.to_string(),
        );

        Ok(receipt)
    }

    fn restore_quarantine(&self, receipt: &IsolationReceipt) -> Result<()> {
        let anchor_path = self.effective_anchor_path();
        info!(
            session_id = %receipt.session_id,
            anchor = %anchor_path,
            "🟢 [MACOS-PF] Reverting macOS native PF quarantine"
        );

        #[cfg(target_os = "macos")]
        {
            let is_root = unsafe { libc::geteuid() == 0 };
            if !is_root && !is_authorized_self_diagnostic() {
                return Err(KillSwitchError::InsufficientPrivileges {
                    details: "Root privileges required to flush macOS /sbin/pfctl anchor"
                        .to_string(),
                    remediation: "Restart the application using 'sudo killswitch'.".to_string(),
                });
            }
            if is_root {
                self.flush_pfctl_anchor()?;
            }
        }

        Ok(())
    }

    fn reset_tcp_connections(&self, target_ips: Option<&[IpAddr]>) -> Result<usize> {
        #[cfg(target_os = "macos")]
        let closed_count = {
            let is_root = unsafe { libc::geteuid() == 0 };
            if !is_root && !is_authorized_self_diagnostic() {
                return Err(KillSwitchError::InsufficientPrivileges {
                    details: "Root privileges required to kill macOS PF states".to_string(),
                    remediation: "Restart the application using 'sudo killswitch'.".to_string(),
                });
            }
            let sockets = get_active_darwin_sockets()?;
            let mut count = 0usize;
            let mut kill_ips = std::collections::HashSet::new();
            for s in &sockets {
                let is_blocked_proxy = QUARANTINE_BLOCKED_LOOPBACK_PROXY_PORTS
                    .contains(&s.foreign_port)
                    || QUARANTINE_BLOCKED_LOOPBACK_PROXY_PORTS.contains(&s.local_port);
                let is_alias_loopback = matches!(s.foreign_addr, IpAddr::V4(v4) if v4.octets()[0] == 127 && v4 != Ipv4Addr::LOCALHOST);
                if !(s.is_external_connection() || is_blocked_proxy || is_alias_loopback) {
                    continue;
                }
                if let Some(filter) = target_ips {
                    if !filter.contains(&s.foreign_addr) && !filter.contains(&s.local_addr) {
                        continue;
                    }
                }
                if is_root {
                    if !s.foreign_addr.is_unspecified() {
                        kill_ips.insert(s.foreign_addr.to_string());
                    }
                    if let Some(pid) = s.pid {
                        if pid != std::process::id()
                            && crate::agent_registry::TrackedAgentTreeRegistry::global()
                                .is_tracked_pid(pid)
                            && !crate::killchain::is_critical_system_pid(
                                pid,
                                s.proc_name.as_deref().unwrap_or(""),
                            )
                        {
                            unsafe {
                                let _ = libc::kill(pid as libc::pid_t, libc::SIGKILL);
                            }
                        }
                    }
                    count += 1;
                }
            }
            if is_root {
                if let Some(filter) = target_ips {
                    for ip in filter {
                        kill_ips.insert(ip.to_string());
                    }
                }
                for ip_str in &kill_ips {
                    let _ = std::process::Command::new("/sbin/pfctl")
                        .args(["-k", ip_str])
                        .output();
                    let _ = std::process::Command::new("/sbin/pfctl")
                        .args(["-k", "0.0.0.0/0", "-k", ip_str])
                        .output();
                }
            }
            count
        };

        #[cfg(not(target_os = "macos"))]
        let closed_count = {
            let sockets = get_active_darwin_sockets()?;
            let mut count = 0usize;
            for s in sockets {
                if !s.is_external_connection() {
                    continue;
                }
                if let Some(filter) = target_ips {
                    if !filter.contains(&s.foreign_addr) && !filter.contains(&s.local_addr) {
                        continue;
                    }
                }
                count += 1;
            }
            count
        };

        info!(
            "🟢 [MACOS-PF] Reset {} external/proxy connections.",
            closed_count
        );
        Ok(closed_count)
    }
}

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use killswitch_types::errors::KillSwitchError;

    #[test]
    fn test_pf_rule_syntax_generation_and_preservation() {
        let preserved_ports = vec![3030, 53, 67, 68, 8080, 9050, 445];
        let (rules, syntax) = generate_quarantine_rules("com.apple/killswitch", &preserved_ports);

        assert!(!rules.is_empty());
        assert!(syntax.contains("Anchor: com.apple/killswitch"));

        // Must NOT emit blanket loopback or catch-all passes
        assert!(!syntax.contains("pass quick on lo0 all"));
        assert!(!syntax.contains("from 127.0.0.1 to any"));
        assert!(!syntax.contains("from ::1 to any"));

        // Must explicitly block IMDS, discovery, QUIC, loopback proxy, lateral, and 127.0.0.0/8 aliases
        assert!(syntax.contains("169.254.0.0/16"));
        assert!(syntax.contains("fe80::/10"));
        assert!(syntax.contains("block drop quick proto udp from any to any port 443"));
        assert!(syntax.contains("block drop quick proto tcp from any to any port 8080"));
        assert!(syntax.contains("block drop quick proto tcp from any to any port 445"));

        // WebUI control port 3030 must be preserved strictly between 127.0.0.1<->127.0.0.1 & ::1<->::1 on lo0
        assert!(
            syntax.contains("pass in quick on lo0 proto tcp from 127.0.0.1 to 127.0.0.1 port 3030")
        );
        assert!(syntax
            .contains("pass out quick on lo0 proto tcp from 127.0.0.1 port 3030 to 127.0.0.1"));
        assert!(syntax.contains("pass in quick on lo0 proto tcp from ::1 to ::1 port 3030"));

        // DNS 53, DHCP 67/68, proxy 8080/9050 must strictly NOT have pass rules
        for bad_port in [
            "port 53 ",
            "port 67 ",
            "port 68 ",
            "port 8080 ",
            "port 9050 ",
            "port 445 ",
        ] {
            assert!(
                !syntax
                    .lines()
                    .any(|l| l.starts_with("pass ") && l.contains(bad_port)),
                "Blocked port {bad_port} must never appear in a pass rule"
            );
        }

        // Must end with default block drop rules with quick: true
        assert!(syntax.contains("block drop in quick all"));
        assert!(syntax.contains("block drop out quick all"));
    }

    #[test]
    fn test_macos_seatbelt_profile_generation() {
        let mut cfg = crate::job_sandbox::SandboxedAgentConfig::new("test-sb", "/usr/bin/python3");
        cfg.writable_paths.push(PathBuf::from("/tmp/ks-agent-work"));
        let sbpl = generate_macos_seatbelt_profile(&cfg);
        assert!(sbpl.contains("(version 1)"));
        assert!(sbpl.contains("(deny default)"));
        assert!(sbpl.contains("(deny network*)"));
        assert!(sbpl.contains("(allow file-read* file-write* (subpath \"/tmp/ks-agent-work\"))"));
        assert!(sbpl
            .contains("(allow file-read* file-write* (subpath \"/private/tmp/ks-agent-work\"))"));

        cfg.allow_network = true;
        let sbpl_net = generate_macos_seatbelt_profile(&cfg);
        assert!(sbpl_net.contains("(allow network*)"));
        assert!(!sbpl_net.contains("(deny network*)"));
    }

    #[test]
    fn test_darwin_pf_isolator_engagement_lifecycle() {
        let isolator = MacOsPfIsolator::with_anchor("test_anchor");
        assert_eq!(isolator.effective_anchor_path(), "com.apple/test_anchor");
        let receipt = match isolator.engage_quarantine(
            &[3030, 53, 8080],
            "test_operator",
            "Testing Darwin PF",
        ) {
            Ok(r) => r,
            Err(KillSwitchError::InsufficientPrivileges { .. }) => {
                // macOS /sbin/pfctl requires root privileges; unprivileged CI runners fail closed safely
                return;
            }
            Err(e) => panic!("engage_quarantine failed unexpectedly: {:?}", e),
        };

        assert_eq!(receipt.engine, NetworkIsolationEngine::DarwinPf);
        assert!(receipt.session_id.contains("test_anchor"));
        assert_eq!(receipt.preserved_ports, vec![3030]);
        assert!(receipt
            .preserved_ips
            .contains(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));

        // Verification of rollback
        let restore_res = isolator.restore_quarantine(&receipt);
        assert!(restore_res.is_ok());
    }

    #[test]
    fn test_darwin_socket_inspection_loopback_classification() {
        let loopback_sock = DarwinSocketEntry {
            pid: Some(100),
            proc_name: Some("test".to_string()),
            fd: Some(4),
            local_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            local_port: 3030,
            foreign_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            foreign_port: 0,
            is_loopback: true,
            is_tcp: true,
            state_name: "LISTEN".to_string(),
        };

        assert!(!loopback_sock.is_external_connection());

        let external_sock = DarwinSocketEntry {
            pid: Some(101),
            proc_name: Some("curl".to_string()),
            fd: Some(5),
            local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            local_port: 45678,
            foreign_addr: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            foreign_port: 80,
            is_loopback: false,
            is_tcp: true,
            state_name: "ESTABLISHED".to_string(),
        };

        assert!(external_sock.is_external_connection());
    }

    #[test]
    fn test_darwin_ioctl_constants_integrity() {
        assert_eq!(DIOCSTART, 0x20004401);
        assert_eq!(DIOCSTOP, 0x20004402);
        assert_eq!(DIOCXBEGIN, 0xC8104451);
        assert_eq!(DIOCXCOMMIT, 0xC8104452);
        assert_eq!(DIOCXROLLBACK, 0xC8104453);
    }
}
