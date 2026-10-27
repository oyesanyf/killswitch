//! REA Layer 2: Path Security, Traversal Defense, and Anti-Masquerade Detection.
//!
//! Enforces:
//! - Null byte and ASCII control character rejection.
//! - Percent-encoded traversal blocking (`%2e`, `%2f`, `%5c`, `%00`).
//! - Windows device namespaces blocking (`\\.\`, `\\?\`, `\Device\`, `globalroot`).
//! - UNC/SMB network share blocking to prevent NTLMv2 credential relay.
//! - NTFS Alternate Data Stream (ADS) blocking.
//! - Parent directory traversal (`..`) and DOS device name blocking.
//! - Anti-masquerade spoof detection against canonical protected binaries.

use anyhow::{anyhow, Result};
use dashmap::DashSet;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

/// Canonical protected binary names across Windows, Linux, and macOS.
static CANONICAL_PROTECTED_BINARY_NAMES: OnceLock<DashSet<String>> = OnceLock::new();

/// Returns the global concurrent set of canonically protected binary names.
pub fn get_canonical_protected_binary_names() -> &'static DashSet<String> {
    CANONICAL_PROTECTED_BINARY_NAMES.get_or_init(|| {
        let set = DashSet::new();
        let names = [
            // Windows system anchors
            "svchost.exe",
            "lsass.exe",
            "explorer.exe",
            "dwm.exe",
            "services.exe",
            "smss.exe",
            "csrss.exe",
            "wininit.exe",
            "winlogon.exe",
            "taskmgr.exe",
            "system",
            "runtimebroker.exe",
            "sihost.exe",
            "conhost.exe",
            "securityhealthservice.exe",
            "smartscreen.exe",
            // Windows & cross-platform developer tools
            "cargo.exe",
            "rustc.exe",
            "rustup.exe",
            "rustdoc.exe",
            "code.exe",
            "antigravity.exe",
            "git.exe",
            "node.exe",
            "python.exe",
            "cl.exe",
            "link.exe",
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            // Linux system daemons & tools
            "systemd",
            "init",
            "systemd-journald",
            "systemd-resolved",
            "sshd",
            "bash",
            "sh",
            "cargo",
            "rustc",
            "git",
            "python3",
            // macOS system daemons & desktop
            "launchd",
            "windowserver",
            "loginwindow",
            "kernel_task",
            "finder",
            "dock",
            "terminal",
            "iterm2",
        ];
        for name in &names {
            set.insert(name.to_ascii_lowercase());
        }
        set
    })
}

/// Check if a binary or process name is canonically protected against masquerading.
pub fn is_canonical_protected_binary_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    get_canonical_protected_binary_names().contains(&lower)
}

/// Validate a target path before REA opens or probes it on disk.
///
/// Strictly rejects:
/// - Null bytes or ASCII control characters (`< 0x20` or `0x7f`)
/// - Percent-encoded traversal (`%2e`, `%2f`, `%5c`, `%00`)
/// - Windows Device namespaces (`\\.\`, `\\?\`, `GLOBALROOT`, `\Device\`, `\??\`)
/// - UNC / SMB network shares (`\\server\share`, `//server/share`, `smb://`, `file:////`)
/// - NTFS Alternate Data Streams (`:` anywhere except index 1 of `[A-Za-z]:`)
/// - Parent directory traversal (`..`)
/// - Reserved DOS/Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`..`COM9`, `LPT1`..`LPT9`)
/// - Symlink escapes (`is_symlink()`)
pub fn validate_rea_target_path(raw_path: &str) -> Result<PathBuf> {
    let trimmed = raw_path.trim().trim_matches('"');
    if trimmed.is_empty() {
        return Err(anyhow!("REA_SANDBOX_PATH_VIOLATION: target path cannot be empty"));
    }

    // 1. Control chars and null bytes
    if trimmed.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(anyhow!(
            "REA_SANDBOX_PATH_VIOLATION: null byte or control character in path"
        ));
    }

    // 2. Percent-encoded traversal
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%00")
    {
        return Err(anyhow!(
            "REA_SANDBOX_PATH_VIOLATION: percent-encoded path traversal blocked"
        ));
    }

    // 3. Windows device namespaces
    if lower.starts_with(r"\\.\")
        || lower.starts_with(r"\\?\")
        || lower.starts_with("//./")
        || lower.starts_with("//?/")
        || lower.contains("globalroot")
        || lower.starts_with(r"\device\")
        || lower.starts_with(r"\??\")
    {
        return Err(anyhow!(
            "REA_SANDBOX_PATH_VIOLATION: Windows device namespace path blocked ('{}')",
            trimmed
        ));
    }

    // 4. UNC / SMB / Remote shares
    if trimmed.starts_with(r"\\")
        || trimmed.starts_with("//")
        || lower.starts_with("smb://")
        || lower.starts_with("file://")
        || lower.starts_with("dav://")
        || lower.starts_with("http://")
        || lower.starts_with("https://")
    {
        return Err(anyhow!(
            "REA_SANDBOX_PATH_VIOLATION: UNC/SMB/remote network path blocked to prevent NTLMv2 credential leak ('{}')",
            trimmed
        ));
    }

    // 5. NTFS Alternate Data Streams (ADS)
    for (idx, ch) in trimmed.char_indices() {
        if ch == ':' {
            let valid_drive_colon = idx == 1 && trimmed.as_bytes()[0].is_ascii_alphabetic();
            if !valid_drive_colon {
                return Err(anyhow!(
                    "REA_SANDBOX_PATH_VIOLATION: NTFS Alternate Data Stream (ADS) or illegal colon blocked ('{}')",
                    trimmed
                ));
            }
        }
    }

    // 6. Parent traversal & DOS device names
    for seg in trimmed.split(['\\', '/']) {
        if seg == ".." {
            return Err(anyhow!(
                "REA_SANDBOX_PATH_VIOLATION: parent directory traversal ('..') blocked ('{}')",
                trimmed
            ));
        }
        let stem = seg
            .split('.')
            .next()
            .unwrap_or(seg)
            .trim_end_matches([' ', '.'])
            .to_ascii_lowercase();
        if matches!(
            stem.as_str(),
            "con"
                | "prn"
                | "aux"
                | "nul"
                | "conin$"
                | "conout$"
                | "com1"
                | "com2"
                | "com3"
                | "com4"
                | "com5"
                | "com6"
                | "com7"
                | "com8"
                | "com9"
                | "lpt1"
                | "lpt2"
                | "lpt3"
                | "lpt4"
                | "lpt5"
                | "lpt6"
                | "lpt7"
                | "lpt8"
                | "lpt9"
        ) {
            return Err(anyhow!(
                "REA_SANDBOX_PATH_VIOLATION: reserved DOS/Windows device name '{}' blocked",
                seg
            ));
        }
    }

    let path_buf = PathBuf::from(trimmed);
    for comp in path_buf.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(anyhow!(
                "REA_SANDBOX_PATH_VIOLATION: parent directory component ('..') blocked"
            ));
        }
    }

    // 7. Symlink escape check
    if let Ok(sym_meta) = std::fs::symlink_metadata(&path_buf) {
        if sym_meta.file_type().is_symlink() {
            return Err(anyhow!(
                "REA_SANDBOX_PATH_VIOLATION: symlink or reparse-point escape blocked ('{}')",
                trimmed
            ));
        }
    }

    Ok(path_buf)
}

/// Returns `true` if `path_str` is located in an untrusted writable or temp directory.
pub fn is_untrusted_writable_or_temp_path(path_str: &str) -> bool {
    crate::win_trust::is_untrusted_writable_location(path_str)
}

/// Detect whether a target binary or process is masquerading as a protected OS or developer binary
/// from an untrusted directory or with a non-PE/corrupted header.
pub fn detect_binary_masquerade_spoof(
    target_label: &str,
    path: Option<&Path>,
    bytes: Option<&[u8]>,
) -> Option<String> {
    let effective_str = path
        .map(|p| p.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| target_label.to_string());
    let raw = effective_str.trim().trim_matches('"');
    if raw.is_empty() {
        return None;
    }

    let norm = raw.replace('/', "\\");
    let base = norm.rsplit('\\').next().unwrap_or(raw).trim();
    let base_lower = base.to_ascii_lowercase();

    // Check double extensions: e.g. cargo.exe.scr, svchost.exe.bat
    if base_lower.contains(".exe.") || base_lower.contains(".dll.") {
        return Some(format!(
            "REA_MASQUERADE_SPOOF_DETECTED: Target '{}' has suspicious double extension",
            base
        ));
    }

    let is_protected_name = is_canonical_protected_binary_name(base);
    let has_dir_sep = raw.contains('\\') || raw.contains('/');

    if is_protected_name && has_dir_sep {
        if is_untrusted_writable_or_temp_path(raw) {
            return Some(format!(
                "REA_MASQUERADE_SPOOF_DETECTED: Protected binary '{}' is executing from untrusted writable/temp path '{}'",
                base_lower, raw
            ));
        }

        let p = Path::new(raw);
        if p.is_file() {
            let trust_verdict = crate::win_trust::verify_binary_cryptographic_trust(p);
            if !trust_verdict.is_trusted() {
                return Some(format!(
                    "REA_MASQUERADE_SPOOF_DETECTED: Protected binary '{}' at '{}' lacks valid cryptographic signature or hash inventory verification",
                    base_lower, raw
                ));
            }
        }
    }

    // Check payload header integrity & format validity
    if is_protected_name && (base_lower.ends_with(".exe") || base_lower.ends_with(".dll") || !base_lower.contains('.')) {
        if let Some(buf) = bytes {
            if !buf.is_empty() {
                if !buf.starts_with(b"MZ") && !buf.starts_with(b"\x7fELF") {
                    return Some(format!(
                        "REA_MASQUERADE_SPOOF_DETECTED: Protected binary '{}' has non-executable payload header (expected PE 'MZ' or ELF magic)",
                        base_lower
                    ));
                }
                match crate::rea::binary_format::inspect_binary_format_safe(buf) {
                    Ok(info) => {
                        if info.section_count > crate::rea::MAX_PE_SECTIONS {
                            return Some(format!(
                                "REA_MASQUERADE_SPOOF_DETECTED: Binary '{}' declares excessive section count ({} > {})",
                                base_lower, info.section_count, crate::rea::MAX_PE_SECTIONS
                            ));
                        }
                    }
                    Err(err) => {
                        return Some(format!(
                            "REA_MASQUERADE_SPOOF_DETECTED: Protected binary '{}' failed binary format validation: {}",
                            base_lower, err
                        ));
                    }
                }
            }
        } else {
            // Path check on disk if bytes not directly supplied
            let p = Path::new(raw);
            if p.is_file() {
                if let Ok(meta) = std::fs::metadata(p) {
                    if meta.len() > crate::rea::MAX_REA_FILE_BYTES {
                        return Some(format!(
                            "REA_MASQUERADE_SPOOF_DETECTED: Protected binary '{}' exceeds maximum allowed size ({} > {})",
                            base_lower, meta.len(), crate::rea::MAX_REA_FILE_BYTES
                        ));
                    }
                    if let Ok(file_bytes) = std::fs::read(p) {
                        if !file_bytes.is_empty() {
                            if !file_bytes.starts_with(b"MZ") && !file_bytes.starts_with(b"\x7fELF") {
                                return Some(format!(
                                    "REA_MASQUERADE_SPOOF_DETECTED: Protected binary '{}' has non-executable payload header (expected PE 'MZ' or ELF magic)",
                                    base_lower
                                ));
                            }
                            if let Err(err) = crate::rea::binary_format::inspect_binary_format_safe(&file_bytes) {
                                return Some(format!(
                                    "REA_MASQUERADE_SPOOF_DETECTED: Protected binary '{}' failed binary format validation: {}",
                                    base_lower, err
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_rea_target_path_rejections() {
        assert!(validate_rea_target_path("").is_err());
        assert!(validate_rea_target_path("foo\0bar").is_err());
        assert!(validate_rea_target_path("..\\windows\\system32").is_err());
        assert!(validate_rea_target_path("C:\\foo\\%2e%2e\\bar").is_err());
        assert!(validate_rea_target_path(r"\\192.168.1.5\share\mal.exe").is_err());
        assert!(validate_rea_target_path("smb://nas/share/mal.exe").is_err());
        assert!(validate_rea_target_path(r"\\.\PhysicalDrive0").is_err());
        assert!(validate_rea_target_path(r"\\?\C:\secret.txt").is_err());
        assert!(validate_rea_target_path("C:\\evil.exe:hidden_stream").is_err());
        assert!(validate_rea_target_path("con.txt").is_err());
        assert!(validate_rea_target_path("NUL").is_err());
    }

    #[test]
    fn test_validate_rea_target_path_valid() {
        assert!(validate_rea_target_path("C:\\Windows\\System32\\svchost.exe").is_ok());
        assert!(validate_rea_target_path("D:\\projects\\agent\\src\\main.rs").is_ok());
        assert!(validate_rea_target_path("/usr/bin/cargo").is_ok());
    }

    #[test]
    fn test_detect_binary_masquerade_spoof() {
        // Masquerade in temp dir
        let temp_spoof = detect_binary_masquerade_spoof(
            "svchost.exe",
            Some(Path::new("C:\\Users\\User\\AppData\\Local\\Temp\\svchost.exe")),
            Some(b"MZfake"),
        );
        assert!(temp_spoof.is_some());
        assert!(temp_spoof.unwrap().contains("untrusted writable/temp path"));

        // Double extension
        let double_ext = detect_binary_masquerade_spoof(
            "cargo.exe.scr",
            None,
            None,
        );
        assert!(double_ext.is_some());
        assert!(double_ext.unwrap().contains("double extension"));

        // Bad payload header
        let bad_hdr = detect_binary_masquerade_spoof(
            "svchost.exe",
            None,
            Some(b"NOT_A_PE_HEADER"),
        );
        assert!(bad_hdr.is_some());
        assert!(bad_hdr.unwrap().contains("non-executable payload header"));
    }
}
