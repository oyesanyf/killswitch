//! Dynamic Parent-Child Security Context & Token Delta Observation.
//!
//! Compares parent vs child security contexts in real time:
//! - Linux / POSIX:
//!   - EUID delta: `parent.euid != 0 && child.euid == 0`.
//!   - CapEff bitmask expansion: `(child.capabilities & !parent.capabilities) != 0`.
//!   - Namespace transitions: Inode divergence in `/proc/<pid>/ns/{user, mnt, pid, net}`.
//! - Windows:
//!   - `TokenIntegrityLevel`: Medium (`0x2000`) -> High (`0x3000`) or System (`0x4000`).
//!   - `TokenElevation`: Parent unelevated -> child elevated.
//!   - `TokenSessionId`: Parent interactive (`SessionId != 0`) -> child `SessionId == 0`.

use std::collections::HashMap;

/// Granular privilege escalation security delta detected between parent and child processes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SecurityContextDelta {
    LinuxEuidEscalation { parent_euid: u32, child_euid: u32 },
    LinuxCapabilityExpansion { added_capabilities: u64 },
    LinuxNamespaceTransition { namespaces: Vec<String> },
    WindowsIntegrityEscalation { parent_rid: u32, child_rid: u32 },
    WindowsTokenElevation,
    WindowsSession0Transition { parent_session: u32 },
    CleanIdentityPreserved,
}

impl SecurityContextDelta {
    pub fn is_privilege_escalation(&self) -> bool {
        !matches!(self, Self::CleanIdentityPreserved)
    }

    pub fn description(&self) -> String {
        match self {
            Self::LinuxEuidEscalation {
                parent_euid,
                child_euid,
            } => {
                format!(
                    "Linux EUID escalation from {} to {}",
                    parent_euid, child_euid
                )
            }
            Self::LinuxCapabilityExpansion { added_capabilities } => {
                format!(
                    "Linux CapEff expanded by bitmask 0x{:016X}",
                    added_capabilities
                )
            }
            Self::LinuxNamespaceTransition { namespaces } => {
                format!(
                    "Linux namespace transition across: {}",
                    namespaces.join(", ")
                )
            }
            Self::WindowsIntegrityEscalation {
                parent_rid,
                child_rid,
            } => {
                format!(
                    "Windows integrity escalation from RID 0x{:04X} to 0x{:04X}",
                    parent_rid, child_rid
                )
            }
            Self::WindowsTokenElevation => {
                "Windows TokenElevation: child process elevated".to_string()
            }
            Self::WindowsSession0Transition { parent_session } => {
                format!(
                    "Windows Session 0 transition from session {}",
                    parent_session
                )
            }
            Self::CleanIdentityPreserved => {
                "Clean identity preserved (no privilege escalation)".to_string()
            }
        }
    }
}

/// Snapshot of a process's security context.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProcessSecurityContext {
    pub pid: u32,
    pub euid: u32,
    pub capabilities: u64,
    pub namespaces: HashMap<String, u64>,
    pub integrity_rid: u32,
    pub is_elevated: bool,
    pub session_id: u32,
}

impl Default for ProcessSecurityContext {
    fn default() -> Self {
        Self {
            pid: 0,
            euid: 1000,
            capabilities: 0,
            namespaces: HashMap::new(),
            integrity_rid: 0x2000, // Medium Integrity
            is_elevated: false,
            session_id: 1,
        }
    }
}

/// Evaluates security context differences between parent and child processes.
pub fn evaluate_security_context_delta(
    parent: &ProcessSecurityContext,
    child: &ProcessSecurityContext,
) -> Vec<SecurityContextDelta> {
    let mut deltas = Vec::new();

    // 1. Linux EUID Escalation (e.g. parent EUID 1000 -> child EUID 0)
    if parent.euid != 0 && child.euid == 0 {
        deltas.push(SecurityContextDelta::LinuxEuidEscalation {
            parent_euid: parent.euid,
            child_euid: child.euid,
        });
    }

    // 2. Linux CapEff Bitmask Expansion
    let added_caps = child.capabilities & !parent.capabilities;
    if added_caps != 0 {
        deltas.push(SecurityContextDelta::LinuxCapabilityExpansion {
            added_capabilities: added_caps,
        });
    }

    // 3. Linux Namespace Inode Transitions
    let mut transitioned_ns = Vec::new();
    for (ns, &child_inode) in &child.namespaces {
        if let Some(&parent_inode) = parent.namespaces.get(ns) {
            if child_inode != parent_inode {
                transitioned_ns.push(ns.clone());
            }
        }
    }
    if !transitioned_ns.is_empty() {
        transitioned_ns.sort();
        deltas.push(SecurityContextDelta::LinuxNamespaceTransition {
            namespaces: transitioned_ns,
        });
    }

    // 4. Windows TokenIntegrityLevel Escalation (< High 0x3000 -> >= High 0x3000)
    if parent.integrity_rid < 0x3000 && child.integrity_rid >= 0x3000 {
        deltas.push(SecurityContextDelta::WindowsIntegrityEscalation {
            parent_rid: parent.integrity_rid,
            child_rid: child.integrity_rid,
        });
    }

    // 5. Windows TokenElevation Delta
    if !parent.is_elevated && child.is_elevated {
        deltas.push(SecurityContextDelta::WindowsTokenElevation);
    }

    // 6. Windows Session 0 Transition
    if parent.session_id != 0 && child.session_id == 0 {
        deltas.push(SecurityContextDelta::WindowsSession0Transition {
            parent_session: parent.session_id,
        });
    }

    if deltas.is_empty() {
        deltas.push(SecurityContextDelta::CleanIdentityPreserved);
    }

    deltas
}

/// Observe real-time parent-to-child token delta for live PIDs.
pub fn observe_parent_child_token_delta(
    parent_pid: u32,
    child_pid: u32,
) -> Vec<SecurityContextDelta> {
    let parent_ctx =
        query_process_security_context(parent_pid).unwrap_or_else(|_| ProcessSecurityContext {
            pid: parent_pid,
            ..Default::default()
        });

    let child_ctx =
        query_process_security_context(child_pid).unwrap_or_else(|_| ProcessSecurityContext {
            pid: child_pid,
            ..Default::default()
        });

    evaluate_security_context_delta(&parent_ctx, &child_ctx)
}

/// Queries live security context from the OS kernel for a specific PID.
pub fn query_process_security_context(pid: u32) -> Result<ProcessSecurityContext, String> {
    if pid <= 4 {
        return Ok(ProcessSecurityContext {
            pid,
            euid: 0,
            capabilities: u64::MAX,
            namespaces: HashMap::new(),
            integrity_rid: 0x4000, // System
            is_elevated: true,
            session_id: 0,
        });
    }

    #[cfg(target_os = "windows")]
    {
        query_windows_token_security_context(pid)
    }

    #[cfg(target_os = "linux")]
    {
        query_linux_security_context(pid)
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Ok(ProcessSecurityContext {
            pid,
            ..Default::default()
        })
    }
}

// ---------------------------------------------------------------------------
// Windows OpenProcessToken & Token Information Querying
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn query_windows_token_security_context(pid: u32) -> Result<ProcessSecurityContext, String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TokenIntegrityLevel, TokenSessionId, TOKEN_ELEVATION,
        TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let h_proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h_proc.is_null() {
            return Err(format!("OpenProcess failed for PID {}", pid));
        }

        let mut h_token = std::ptr::null_mut();
        let tok_res = OpenProcessToken(h_proc, TOKEN_QUERY, &mut h_token);
        CloseHandle(h_proc);

        if tok_res == 0 || h_token.is_null() {
            return Err(format!("OpenProcessToken failed for PID {}", pid));
        }

        let mut integrity_rid = 0x2000; // Default Medium
        let mut is_elevated = false;
        let mut session_id = 1;

        // 1. Query TokenIntegrityLevel
        let mut label_buf = [0u8; 128];
        let mut ret_len = 0u32;
        if GetTokenInformation(
            h_token,
            TokenIntegrityLevel,
            label_buf.as_mut_ptr() as *mut _,
            label_buf.len() as u32,
            &mut ret_len,
        ) != 0
        {
            let label = &*(label_buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
            if !label.Label.Sid.is_null() {
                let sub_auth_count =
                    *windows_sys::Win32::Security::GetSidSubAuthorityCount(label.Label.Sid);
                if sub_auth_count > 0 {
                    let sub_auth_ptr = windows_sys::Win32::Security::GetSidSubAuthority(
                        label.Label.Sid,
                        (sub_auth_count - 1) as u32,
                    );
                    integrity_rid = *sub_auth_ptr;
                }
            }
        }

        // 2. Query TokenElevation
        let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut elev_len = 0u32;
        if GetTokenInformation(
            h_token,
            TokenElevation,
            &mut elev as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut elev_len,
        ) != 0
        {
            is_elevated = elev.TokenIsElevated != 0;
        }

        // 3. Query TokenSessionId
        let mut sess = 0u32;
        let mut sess_len = 0u32;
        if GetTokenInformation(
            h_token,
            TokenSessionId,
            &mut sess as *mut _ as *mut _,
            std::mem::size_of::<u32>() as u32,
            &mut sess_len,
        ) != 0
        {
            session_id = sess;
        }

        CloseHandle(h_token);

        Ok(ProcessSecurityContext {
            pid,
            euid: if is_elevated { 0 } else { 1000 },
            capabilities: 0,
            namespaces: HashMap::new(),
            integrity_rid,
            is_elevated,
            session_id,
        })
    }
}

// ---------------------------------------------------------------------------
// Linux /proc/<pid>/status & /proc/<pid>/ns Querying
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn query_linux_security_context(pid: u32) -> Result<ProcessSecurityContext, String> {
    use std::fs;

    let status_path = format!("/proc/{}/status", pid);
    let status_str = fs::read_to_string(&status_path)
        .map_err(|e| format!("Could not read {}: {}", status_path, e))?;

    let mut euid = 1000;
    let mut capabilities = 0u64;

    for line in status_str.lines() {
        if line.starts_with("Uid:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                // Uid: real effective saved fs
                if let Ok(eff) = parts[2].parse::<u32>() {
                    euid = eff;
                }
            }
        } else if line.starts_with("CapEff:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(caps) = u64::from_str_radix(parts[1], 16) {
                    capabilities = caps;
                }
            }
        }
    }

    let mut namespaces = HashMap::new();
    let ns_dir = format!("/proc/{}/ns", pid);
    if let Ok(entries) = fs::read_dir(ns_dir) {
        for entry in entries.flatten() {
            let ns_name = entry.file_name().to_string_lossy().to_string();
            if let Ok(target) = fs::read_link(entry.path()) {
                let target_str = target.to_string_lossy();
                if let Some(start) = target_str.find('[') {
                    if let Some(end) = target_str.rfind(']') {
                        if let Ok(inode) = target_str[start + 1..end].parse::<u64>() {
                            namespaces.insert(ns_name, inode);
                        }
                    }
                }
            }
        }
    }

    Ok(ProcessSecurityContext {
        pid,
        euid,
        capabilities,
        namespaces,
        integrity_rid: if euid == 0 { 0x3000 } else { 0x2000 },
        is_elevated: euid == 0,
        session_id: 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_euid_escalation_detection() {
        let parent = ProcessSecurityContext {
            pid: 100,
            euid: 1000,
            ..Default::default()
        };
        let child = ProcessSecurityContext {
            pid: 101,
            euid: 0,
            ..Default::default()
        };

        let deltas = evaluate_security_context_delta(&parent, &child);
        assert!(deltas.iter().any(|d| matches!(
            d,
            SecurityContextDelta::LinuxEuidEscalation {
                parent_euid: 1000,
                child_euid: 0
            }
        )));
        assert!(deltas.iter().any(|d| d.is_privilege_escalation()));
    }

    #[test]
    fn test_linux_capability_expansion_detection() {
        let parent = ProcessSecurityContext {
            pid: 200,
            capabilities: 0x00000000,
            ..Default::default()
        };
        let child = ProcessSecurityContext {
            pid: 201,
            capabilities: 0x00200000, // CAP_SYS_ADMIN
            ..Default::default()
        };

        let deltas = evaluate_security_context_delta(&parent, &child);
        assert!(deltas.iter().any(|d| matches!(
            d,
            SecurityContextDelta::LinuxCapabilityExpansion {
                added_capabilities: 0x00200000
            }
        )));
    }

    #[test]
    fn test_linux_namespace_transition_detection() {
        let mut parent_ns = HashMap::new();
        parent_ns.insert("mnt".to_string(), 4026531840);
        parent_ns.insert("pid".to_string(), 4026531836);

        let mut child_ns = HashMap::new();
        child_ns.insert("mnt".to_string(), 4026532999); // Transitioned mount namespace
        child_ns.insert("pid".to_string(), 4026531836);

        let parent = ProcessSecurityContext {
            pid: 300,
            namespaces: parent_ns,
            ..Default::default()
        };
        let child = ProcessSecurityContext {
            pid: 301,
            namespaces: child_ns,
            ..Default::default()
        };

        let deltas = evaluate_security_context_delta(&parent, &child);
        assert!(deltas.iter().any(|d| matches!(
            d,
            SecurityContextDelta::LinuxNamespaceTransition { namespaces } if namespaces.contains(&"mnt".to_string())
        )));
    }

    #[test]
    fn test_windows_integrity_escalation_detection() {
        let parent = ProcessSecurityContext {
            pid: 400,
            integrity_rid: 0x2000, // Medium
            ..Default::default()
        };
        let child = ProcessSecurityContext {
            pid: 401,
            integrity_rid: 0x3000, // High
            ..Default::default()
        };

        let deltas = evaluate_security_context_delta(&parent, &child);
        assert!(deltas.iter().any(|d| matches!(
            d,
            SecurityContextDelta::WindowsIntegrityEscalation {
                parent_rid: 0x2000,
                child_rid: 0x3000
            }
        )));
    }

    #[test]
    fn test_windows_token_elevation_and_session0_detection() {
        let parent = ProcessSecurityContext {
            pid: 500,
            is_elevated: false,
            session_id: 1,
            ..Default::default()
        };
        let child = ProcessSecurityContext {
            pid: 501,
            is_elevated: true,
            session_id: 0,
            ..Default::default()
        };

        let deltas = evaluate_security_context_delta(&parent, &child);
        assert!(deltas.contains(&SecurityContextDelta::WindowsTokenElevation));
        assert!(
            deltas.contains(&SecurityContextDelta::WindowsSession0Transition { parent_session: 1 })
        );
    }

    #[test]
    fn test_clean_identity_preservation() {
        let parent = ProcessSecurityContext::default();
        let child = ProcessSecurityContext::default();

        let deltas = evaluate_security_context_delta(&parent, &child);
        assert_eq!(deltas, vec![SecurityContextDelta::CleanIdentityPreserved]);
        assert!(!deltas[0].is_privilege_escalation());
    }
}
