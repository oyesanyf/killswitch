//! Semantic Command Analysis, Privilege Equivalence Classes & Dynamic Binary Probing.
//!
//! Provides structural AST parsing and token/flag evaluation for CLI commands:
//! - Quotes-aware tokenization and shell unwrapping (`sh -c`, `bash -c`, `cmd.exe /c`, `powershell.exe -Command`).
//! - Environment variable assignment prefix extraction (`VAR=val cmd`).
//! - Flag and switch evaluation (`sudo` flags `-u`, `-n`, `-l`; `su` args; `runas /user:`; `wsl -u` / `--user`).
//! - Privilege equivalence classification (`RootOrAdminElevation`, `TargetUserDelegation`, `PrivilegeQueryOrBenign`, `UnprivilegedStandard`).
//! - Dynamic binary metadata probing (SUID/SGID bits, Linux capabilities, Windows PE manifest `<requestedExecutionLevel>`, WSL traits) to catch renamed or custom binaries dynamically.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Privilege equivalence class taxonomy per Requirement R3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PrivilegeEquivalenceClass {
    /// Escalates to root, UID 0, Administrator, or NT AUTHORITY\SYSTEM.
    /// Equivalent members: `sudo` (without benign query flags), `su [root]`, `doas [root]`,
    /// `pkexec [root]`, `runas /user:Administrator`, `wsl -u root`, `wsl -u 0`, or any target
    /// where `is_privileged_target() == true`.
    RootOrAdminElevation = 1,
    /// Executes as a delegated non-root user or service account (e.g. `sudo -u <user>`,
    /// `su <user>`, `runas /user:<user>`, `wsl -u <user>`, `doas -u <user>`).
    TargetUserDelegation = 2,
    /// Non-executing informational/query commands (e.g. `sudo -l`, `sudo -V`, `sudo -h`,
    /// `pkexec --version`, `wsl --status`, `wsl -l -v`, `su --help`).
    PrivilegeQueryOrBenign = 3,
    /// Standard unprivileged process execution (e.g. `cat`, `cargo test`, `git status`).
    UnprivilegedStandard = 4,
}

impl PrivilegeEquivalenceClass {
    /// Returns true if the command performs privileged execution (either RootOrAdminElevation or TargetUserDelegation).
    pub fn is_privileged_execution(&self) -> bool {
        matches!(self, Self::RootOrAdminElevation | Self::TargetUserDelegation)
    }

    /// Returns true if the command escalates directly to root or Administrator.
    pub fn is_root_or_admin(&self) -> bool {
        matches!(self, Self::RootOrAdminElevation)
    }

    /// Returns true if the command delegates to a non-root target user.
    pub fn is_target_delegation(&self) -> bool {
        matches!(self, Self::TargetUserDelegation)
    }

    /// Returns true if the command is a non-executing query or help invocation.
    pub fn is_benign_query(&self) -> bool {
        matches!(self, Self::PrivilegeQueryOrBenign)
    }
}

/// Declared elevation requirement in Windows PE manifest resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ElevationRequirement {
    RequireAdministrator,
    HighestAvailable,
    AsInvoker,
    None,
}

/// Dynamic binary metadata probe capturing filesystem attributes and executable headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicBinaryMetadataProbe {
    pub is_suid: bool,
    pub is_sgid: bool,
    pub file_uid: u32,
    pub has_linux_capabilities: bool,
    pub linux_capabilities_mask: u64,
    pub elevation_requirement: ElevationRequirement,
    pub invokes_wsl_subsystem: bool,
    pub invokes_hyperv_compute: bool,
}

impl Default for DynamicBinaryMetadataProbe {
    fn default() -> Self {
        Self {
            is_suid: false,
            is_sgid: false,
            file_uid: 0,
            has_linux_capabilities: false,
            linux_capabilities_mask: 0,
            elevation_requirement: ElevationRequirement::None,
            invokes_wsl_subsystem: false,
            invokes_hyperv_compute: false,
        }
    }
}

impl DynamicBinaryMetadataProbe {
    /// Returns true if binary exhibits privileged execution or elevation traits on disk.
    pub fn is_privileged_target(&self) -> bool {
        (self.is_suid && self.file_uid == 0)
            || self.has_linux_capabilities
            || matches!(
                self.elevation_requirement,
                ElevationRequirement::RequireAdministrator | ElevationRequirement::HighestAvailable
            )
            || self.invokes_wsl_subsystem
    }

    /// Construct probe from POSIX file attributes (mode, file UID, capability mask).
    pub fn from_posix(mode: u32, file_uid: u32, capabilities_mask: u64) -> Self {
        Self {
            is_suid: (mode & 0o4000) != 0,
            is_sgid: (mode & 0o2000) != 0,
            file_uid,
            has_linux_capabilities: capabilities_mask != 0,
            linux_capabilities_mask: capabilities_mask,
            elevation_requirement: ElevationRequirement::None,
            invokes_wsl_subsystem: false,
            invokes_hyperv_compute: false,
        }
    }

    /// Construct probe from PE manifest XML content and imported DLL list.
    pub fn from_pe_manifest(manifest_xml: &str, imported_dlls: &[&str]) -> Self {
        let xml_lc = manifest_xml.to_ascii_lowercase();
        let elevation_requirement = if xml_lc.contains("requireadministrator") {
            ElevationRequirement::RequireAdministrator
        } else if xml_lc.contains("highestavailable") {
            ElevationRequirement::HighestAvailable
        } else if xml_lc.contains("asinvoker") {
            ElevationRequirement::AsInvoker
        } else {
            ElevationRequirement::None
        };

        let invokes_wsl_subsystem = imported_dlls.iter().any(|d| {
            let d_lc = d.to_ascii_lowercase();
            d_lc.contains("wslapi.dll") || d_lc.contains("lxss")
        });

        let invokes_hyperv_compute = imported_dlls.iter().any(|d| {
            let d_lc = d.to_ascii_lowercase();
            d_lc.contains("vmcompute.dll")
        });

        Self {
            is_suid: false,
            is_sgid: false,
            file_uid: 0,
            has_linux_capabilities: false,
            linux_capabilities_mask: 0,
            elevation_requirement,
            invokes_wsl_subsystem,
            invokes_hyperv_compute,
        }
    }

    /// Probe on-disk binary metadata at specified path.
    pub fn probe_path(path: &Path) -> std::io::Result<Self> {
        if !path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Binary path not found: {}", path.display()),
            ));
        }

        let mut probe = Self::default();

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(fs_meta) = std::fs::metadata(path) {
                let mode = fs_meta.mode();
                probe.is_suid = (mode & 0o4000) != 0;
                probe.is_sgid = (mode & 0o2000) != 0;
                probe.file_uid = fs_meta.uid();
            }

            #[cfg(target_os = "linux")]
            {
                use std::ffi::CString;
                use std::os::unix::ffi::OsStrExt;
                if let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) {
                    let mut buf = [0u8; 64];
                    let attr_name = b"security.capability\0";
                    let res = unsafe {
                        libc::getxattr(
                            c_path.as_ptr(),
                            attr_name.as_ptr() as *const libc::c_char,
                            buf.as_mut_ptr() as *mut libc::c_void,
                            buf.len(),
                        )
                    };
                    if res > 0 {
                        probe.has_linux_capabilities = true;
                        if res >= 8 {
                            let eff = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
                            probe.linux_capabilities_mask = eff as u64;
                        }
                    }
                }
            }
        }

        // Read executable header/manifest bytes (up to 4MB)
        if let Ok(mut file) = std::fs::File::open(path) {
            use std::io::Read;
            let mut buffer = Vec::new();
            if file.by_ref().take(4 * 1024 * 1024).read_to_end(&mut buffer).is_ok() {
                let bytes_probe = Self::probe_bytes(&buffer);
                if bytes_probe.elevation_requirement != ElevationRequirement::None {
                    probe.elevation_requirement = bytes_probe.elevation_requirement;
                }
                if bytes_probe.invokes_wsl_subsystem {
                    probe.invokes_wsl_subsystem = true;
                }
                if bytes_probe.invokes_hyperv_compute {
                    probe.invokes_hyperv_compute = true;
                }
                if bytes_probe.has_linux_capabilities {
                    probe.has_linux_capabilities = true;
                    probe.linux_capabilities_mask = bytes_probe.linux_capabilities_mask;
                }
                if bytes_probe.is_suid {
                    probe.is_suid = true;
                }
            }
        }

        Ok(probe)
    }

    /// Probe in-memory executable bytes for PE manifest or subsystem references.
    pub fn probe_bytes(bytes: &[u8]) -> Self {
        let mut probe = Self::default();
        if bytes.is_empty() {
            return probe;
        }

        // Manifest XML scan (UTF-8 / ASCII)
        let text = String::from_utf8_lossy(bytes);
        if let Some(req) = scan_xml_requested_execution_level(&text) {
            probe.elevation_requirement = req;
        }

        // UTF-16 LE search if not found
        if probe.elevation_requirement == ElevationRequirement::None && bytes.len() >= 4 {
            let u16_chars: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            let utf16_str = String::from_utf16_lossy(&u16_chars);
            if let Some(req) = scan_xml_requested_execution_level(&utf16_str) {
                probe.elevation_requirement = req;
            }
        }

        // Subsystem traits
        let lower_bytes = bytes.to_ascii_lowercase();
        if find_subsequence(&lower_bytes, b"wslapi.dll")
            || find_subsequence(&lower_bytes, b"wsl.exe")
            || find_subsequence(&lower_bytes, b"lxss")
        {
            probe.invokes_wsl_subsystem = true;
        }

        if find_subsequence(&lower_bytes, b"vmcompute.dll")
            || find_subsequence(&lower_bytes, b"compute-system")
        {
            probe.invokes_hyperv_compute = true;
        }

        probe
    }
}

fn scan_xml_requested_execution_level(content: &str) -> Option<ElevationRequirement> {
    let lower = content.to_ascii_lowercase();
    let idx = lower.find("requestedexecutionlevel")?;
    let snippet = &lower[idx..std::cmp::min(lower.len(), idx + 300)];

    if snippet.contains("requireadministrator") {
        Some(ElevationRequirement::RequireAdministrator)
    } else if snippet.contains("highestavailable") {
        Some(ElevationRequirement::HighestAvailable)
    } else if snippet.contains("asinvoker") {
        Some(ElevationRequirement::AsInvoker)
    } else {
        None
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// Structural AST representation of a parsed command line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticCommand {
    /// Raw unparsed command line.
    pub raw_command: String,
    /// Primary executable token (or path).
    pub executable: String,
    /// Command line arguments.
    pub args: Vec<String>,
    /// Target user for delegation or elevation (if specified, e.g. "root", "Administrator", "www-data").
    pub target_user: Option<String>,
    /// Privilege equivalence classification.
    pub privilege_class: PrivilegeEquivalenceClass,
    /// Indicates whether execution traverses a VM/container boundary (e.g. WSL2, Hyper-V).
    pub is_cross_boundary: bool,
    /// Environment variable prefixes stripped prior to executable invocation.
    pub env_vars: Vec<(String, String)>,
    /// Non-interactive flag detected (e.g. `sudo -n`, `doas -n`).
    pub is_non_interactive: bool,
    /// Dynamic binary metadata probe result (if available).
    pub dynamic_probe: Option<DynamicBinaryMetadataProbe>,
}

/// Safely tokenizes command line string, respecting single and double quotes and escapes.
pub fn tokenize_command(cmd: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut chars = cmd.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\\' if !in_single => {
                if let Some(&next) = chars.peek() {
                    chars.next();
                    current.push(next);
                } else {
                    current.push('\\');
                }
            }
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if !current.is_empty() {
                    tokens.push(current);
                    current = String::new();
                }
            }
            _ => {
                current.push(c);
            }
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

/// Attempts to unwrap shell command wrappers (`sh -c "..."`, `bash -c "..."`, `cmd.exe /c "..."`, `powershell.exe -Command "..."`).
fn unwrap_shell_invocation(tokens: &[String]) -> Option<String> {
    if tokens.is_empty() {
        return None;
    }

    let exe_lc = tokens[0].to_ascii_lowercase();
    let base = exe_lc
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&exe_lc)
        .trim_end_matches(".exe");

    match base {
        "sh" | "bash" | "zsh" | "dash" | "ksh" => {
            // Find -c flag
            for i in 1..tokens.len() {
                if tokens[i] == "-c" && i + 1 < tokens.len() {
                    return Some(tokens[i + 1..].join(" "));
                }
            }
        }
        "cmd" => {
            // Find /c or /k flag
            for i in 1..tokens.len() {
                let arg_lc = tokens[i].to_ascii_lowercase();
                if (arg_lc == "/c" || arg_lc == "/k") && i + 1 < tokens.len() {
                    return Some(tokens[i + 1..].join(" "));
                }
            }
        }
        "powershell" | "pwsh" => {
            // Find -Command or -c flag
            for i in 1..tokens.len() {
                let arg_lc = tokens[i].to_ascii_lowercase();
                if (arg_lc == "-command" || arg_lc == "-c") && i + 1 < tokens.len() {
                    return Some(tokens[i + 1..].join(" "));
                }
            }
        }
        _ => {}
    }

    None
}

/// Checks if a token matches environment variable assignment syntax `NAME=VAL`.
fn is_env_var_assignment(token: &str) -> bool {
    if let Some(eq_pos) = token.find('=') {
        if eq_pos > 0 && !token.starts_with('-') && !token.starts_with('/') {
            let name = &token[..eq_pos];
            return name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');
        }
    }
    false
}

/// Parses a command line into a structural `SemanticCommand` AST with default dynamic probing.
pub fn parse_semantic_command(raw: &str) -> SemanticCommand {
    parse_semantic_command_with_probe(raw, None)
}

/// Parses a command line into a structural `SemanticCommand` AST, with optional caller-provided dynamic probe.
pub fn parse_semantic_command_with_probe(
    raw: &str,
    external_probe: Option<&DynamicBinaryMetadataProbe>,
) -> SemanticCommand {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return SemanticCommand {
            raw_command: raw.to_string(),
            executable: String::new(),
            args: Vec::new(),
            target_user: None,
            privilege_class: PrivilegeEquivalenceClass::UnprivilegedStandard,
            is_cross_boundary: false,
            env_vars: Vec::new(),
            is_non_interactive: false,
            dynamic_probe: None,
        };
    }

    let tokens = tokenize_command(trimmed);
    let mut env_vars = Vec::new();

    // 1. Strip environment variable assignments at start (e.g. SUDO_ASKPASS=... VAR=val)
    let mut cmd_idx = 0;
    while cmd_idx < tokens.len() && is_env_var_assignment(&tokens[cmd_idx]) {
        let tok = &tokens[cmd_idx];
        if let Some(eq) = tok.find('=') {
            env_vars.push((tok[..eq].to_string(), tok[eq + 1..].to_string()));
        }
        cmd_idx += 1;
    }

    if cmd_idx >= tokens.len() {
        // Only env vars provided without command
        return SemanticCommand {
            raw_command: raw.to_string(),
            executable: String::new(),
            args: Vec::new(),
            target_user: None,
            privilege_class: PrivilegeEquivalenceClass::UnprivilegedStandard,
            is_cross_boundary: false,
            env_vars,
            is_non_interactive: false,
            dynamic_probe: None,
        };
    }

    let remaining_tokens = &tokens[cmd_idx..];

    // 2. Shell unwrapping check
    if let Some(unwrapped) = unwrap_shell_invocation(remaining_tokens) {
        let mut inner = parse_semantic_command_with_probe(&unwrapped, external_probe);
        inner.raw_command = raw.to_string();
        for ev in env_vars {
            inner.env_vars.push(ev);
        }
        return inner;
    }

    let exe_token = remaining_tokens[0].clone();
    let args: Vec<String> = remaining_tokens[1..].to_vec();

    let exe_lc = exe_token.to_ascii_lowercase();
    let exe_base = exe_lc
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(&exe_lc)
        .trim_end_matches(".exe");

    let mut target_user: Option<String> = None;
    let mut is_non_interactive = false;
    let mut is_cross_boundary = false;
    let mut privilege_class;

    match exe_base {
        "sudo" => {
            // Check benign query flags: -l, -V, -h, --help, --version
            if args.iter().any(|a| {
                matches!(
                    a.as_str(),
                    "-l" | "-v" | "-V" | "-h" | "--help" | "--version"
                )
            }) {
                privilege_class = PrivilegeEquivalenceClass::PrivilegeQueryOrBenign;
            } else {
                // Check non-interactive flag -n
                if args.iter().any(|a| a == "-n") {
                    is_non_interactive = true;
                }

                // Parse target user from -u / --user
                for i in 0..args.len() {
                    if args[i] == "-u" && i + 1 < args.len() {
                        target_user = Some(args[i + 1].trim_matches(['"', '\'']).to_string());
                        break;
                    } else if args[i].starts_with("-u") && args[i].len() > 2 {
                        target_user = Some(args[i][2..].trim_matches(['"', '\'']).to_string());
                        break;
                    } else if args[i].starts_with("--user=") {
                        target_user = Some(
                            args[i]
                                .trim_start_matches("--user=")
                                .trim_matches(['"', '\''])
                                .to_string(),
                        );
                        break;
                    } else if args[i] == "--user" && i + 1 < args.len() {
                        target_user = Some(args[i + 1].trim_matches(['"', '\'']).to_string());
                        break;
                    }
                }

                if let Some(ref u) = target_user {
                    let u_lc = u.to_ascii_lowercase();
                    if u_lc == "root" || u_lc == "0" {
                        privilege_class = PrivilegeEquivalenceClass::RootOrAdminElevation;
                    } else {
                        privilege_class = PrivilegeEquivalenceClass::TargetUserDelegation;
                    }
                } else {
                    privilege_class = PrivilegeEquivalenceClass::RootOrAdminElevation;
                }
            }
        }
        "su" => {
            // Benign query flags: -h, --help, -V, --version
            if args
                .iter()
                .any(|a| matches!(a.as_str(), "-h" | "--help" | "-V" | "--version"))
            {
                privilege_class = PrivilegeEquivalenceClass::PrivilegeQueryOrBenign;
            } else {
                // Collect positional non-flag arguments after skipping options
                let mut non_flags = Vec::new();
                let mut skip_next = false;
                for a in &args {
                    if skip_next {
                        skip_next = false;
                        continue;
                    }
                    if a == "-c" || a == "-s" {
                        skip_next = true;
                        continue;
                    }
                    if a.starts_with('-') {
                        continue;
                    }
                    non_flags.push(a.trim_matches(['"', '\'']).to_string());
                }

                target_user = non_flags.first().cloned();
                if let Some(ref u) = target_user {
                    let u_lc = u.to_ascii_lowercase();
                    if u_lc == "root" || u_lc == "0" {
                        privilege_class = PrivilegeEquivalenceClass::RootOrAdminElevation;
                    } else {
                        privilege_class = PrivilegeEquivalenceClass::TargetUserDelegation;
                    }
                } else {
                    privilege_class = PrivilegeEquivalenceClass::RootOrAdminElevation;
                }
            }
        }
        "doas" => {
            if args
                .iter()
                .any(|a| matches!(a.as_str(), "-h" | "--help" | "-V" | "--version"))
            {
                privilege_class = PrivilegeEquivalenceClass::PrivilegeQueryOrBenign;
            } else {
                if args.iter().any(|a| a == "-n") {
                    is_non_interactive = true;
                }
                for i in 0..args.len() {
                    if args[i] == "-u" && i + 1 < args.len() {
                        target_user = Some(args[i + 1].trim_matches(['"', '\'']).to_string());
                        break;
                    }
                }
                if let Some(ref u) = target_user {
                    let u_lc = u.to_ascii_lowercase();
                    if u_lc == "root" || u_lc == "0" {
                        privilege_class = PrivilegeEquivalenceClass::RootOrAdminElevation;
                    } else {
                        privilege_class = PrivilegeEquivalenceClass::TargetUserDelegation;
                    }
                } else {
                    privilege_class = PrivilegeEquivalenceClass::RootOrAdminElevation;
                }
            }
        }
        "pkexec" => {
            if args
                .iter()
                .any(|a| matches!(a.as_str(), "--version" | "--help" | "-h"))
            {
                privilege_class = PrivilegeEquivalenceClass::PrivilegeQueryOrBenign;
            } else {
                for i in 0..args.len() {
                    if args[i] == "--user" && i + 1 < args.len() {
                        target_user = Some(args[i + 1].trim_matches(['"', '\'']).to_string());
                        break;
                    }
                }
                if let Some(ref u) = target_user {
                    let u_lc = u.to_ascii_lowercase();
                    if u_lc == "root" || u_lc == "0" {
                        privilege_class = PrivilegeEquivalenceClass::RootOrAdminElevation;
                    } else {
                        privilege_class = PrivilegeEquivalenceClass::TargetUserDelegation;
                    }
                } else {
                    privilege_class = PrivilegeEquivalenceClass::RootOrAdminElevation;
                }
            }
        }
        "runas" => {
            let mut matched_admin = false;
            let mut extracted_user = None;

            for a in &args {
                let a_clean = a.trim_matches(['"', '\'']);
                let a_lc = a_clean.to_ascii_lowercase();
                if let Some(idx) = a_lc.find("/user:") {
                    let user_val = a_clean[idx + 6..].trim_matches(['"', '\'']).to_string();
                    let u_lc = user_val.to_ascii_lowercase();
                    if u_lc == "administrator"
                        || u_lc == "admin"
                        || u_lc == "system"
                        || u_lc.contains("system")
                    {
                        matched_admin = true;
                    }
                    extracted_user = Some(user_val);
                    break;
                }
            }

            target_user = extracted_user;
            if matched_admin {
                privilege_class = PrivilegeEquivalenceClass::RootOrAdminElevation;
            } else if target_user.is_some() {
                privilege_class = PrivilegeEquivalenceClass::TargetUserDelegation;
            } else {
                privilege_class = PrivilegeEquivalenceClass::RootOrAdminElevation;
            }
        }
        "wsl" => {
            is_cross_boundary = true;
            // Check query flags: -l, --list, --status, -h, --help, --version, -v
            if args.iter().any(|a| {
                matches!(
                    a.as_str(),
                    "-l" | "--list" | "--status" | "-h" | "--help" | "--version" | "-v"
                )
            }) && !args.iter().any(|a| a == "-e" || a == "--exec")
            {
                privilege_class = PrivilegeEquivalenceClass::PrivilegeQueryOrBenign;
            } else {
                let mut matched_root = false;
                for i in 0..args.len() {
                    let arg = &args[i];
                    if (arg == "-u" || arg == "--user") && i + 1 < args.len() {
                        let u = args[i + 1].trim_matches(['"', '\'']).to_string();
                        let u_lc = u.to_ascii_lowercase();
                        if u_lc == "root" || u_lc == "0" {
                            matched_root = true;
                        }
                        target_user = Some(u);
                        break;
                    } else if arg.starts_with("--user=") {
                        let u = arg
                            .trim_start_matches("--user=")
                            .trim_matches(['"', '\''])
                            .to_string();
                        let u_lc = u.to_ascii_lowercase();
                        if u_lc == "root" || u_lc == "0" {
                            matched_root = true;
                        }
                        target_user = Some(u);
                        break;
                    } else if arg.starts_with("-u") && arg.len() > 2 {
                        let u = arg[2..].trim_matches(['"', '\'']).to_string();
                        let u_lc = u.to_ascii_lowercase();
                        if u_lc == "root" || u_lc == "0" {
                            matched_root = true;
                        }
                        target_user = Some(u);
                        break;
                    }
                }

                if matched_root {
                    privilege_class = PrivilegeEquivalenceClass::RootOrAdminElevation;
                } else if target_user.is_some() {
                    privilege_class = PrivilegeEquivalenceClass::TargetUserDelegation;
                } else {
                    // Default WSL execution without -u invokes the container VM shell
                    privilege_class = PrivilegeEquivalenceClass::RootOrAdminElevation;
                }
            }
        }
        _ => {
            privilege_class = PrivilegeEquivalenceClass::UnprivilegedStandard;
        }
    }

    // 3. Dynamic Binary Metadata Probing Integration
    // If external probe was provided or target binary exists on disk, inspect metadata
    let mut resolved_probe = external_probe.cloned();
    if resolved_probe.is_none() {
        let candidate_path = Path::new(&exe_token);
        if candidate_path.exists() {
            if let Ok(p) = DynamicBinaryMetadataProbe::probe_path(candidate_path) {
                resolved_probe = Some(p);
            }
        }
    }

    if let Some(ref probe) = resolved_probe {
        if probe.is_privileged_target() {
            if probe.is_suid && probe.file_uid == 0 {
                privilege_class = PrivilegeEquivalenceClass::RootOrAdminElevation;
            } else if probe.has_linux_capabilities {
                privilege_class = PrivilegeEquivalenceClass::RootOrAdminElevation;
            } else if matches!(
                probe.elevation_requirement,
                ElevationRequirement::RequireAdministrator | ElevationRequirement::HighestAvailable
            ) {
                privilege_class = PrivilegeEquivalenceClass::RootOrAdminElevation;
            } else if probe.invokes_wsl_subsystem {
                privilege_class = PrivilegeEquivalenceClass::RootOrAdminElevation;
                is_cross_boundary = true;
            } else if probe.is_suid && probe.file_uid != 0 {
                privilege_class = PrivilegeEquivalenceClass::TargetUserDelegation;
            }
        }
    }

    SemanticCommand {
        raw_command: raw.to_string(),
        executable: exe_token,
        args,
        target_user,
        privilege_class,
        is_cross_boundary,
        env_vars,
        is_non_interactive,
        dynamic_probe: resolved_probe,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sudo_elevation_equivalence_classes() {
        let cmd = parse_semantic_command("sudo -n id");
        assert_eq!(cmd.privilege_class, PrivilegeEquivalenceClass::RootOrAdminElevation);
        assert!(cmd.is_non_interactive);
        assert!(cmd.privilege_class.is_privileged_execution());
        assert!(cmd.privilege_class.is_root_or_admin());

        let cmd_delegated = parse_semantic_command("sudo -u www-data cat /var/log/nginx/access.log");
        assert_eq!(cmd_delegated.privilege_class, PrivilegeEquivalenceClass::TargetUserDelegation);
        assert_eq!(cmd_delegated.target_user.as_deref(), Some("www-data"));
        assert!(cmd_delegated.privilege_class.is_privileged_execution());
        assert!(!cmd_delegated.privilege_class.is_root_or_admin());

        let cmd_query = parse_semantic_command("sudo -l");
        assert_eq!(cmd_query.privilege_class, PrivilegeEquivalenceClass::PrivilegeQueryOrBenign);
        assert!(cmd_query.privilege_class.is_benign_query());
        assert!(!cmd_query.privilege_class.is_privileged_execution());
    }

    #[test]
    fn test_wsl_elevation_and_cross_boundary() {
        let cmd_root = parse_semantic_command("wsl -u root apt-get update");
        assert_eq!(cmd_root.privilege_class, PrivilegeEquivalenceClass::RootOrAdminElevation);
        assert!(cmd_root.is_cross_boundary);
        assert_eq!(cmd_root.target_user.as_deref(), Some("root"));

        let cmd_zero = parse_semantic_command("wsl -u 0 id");
        assert_eq!(cmd_zero.privilege_class, PrivilegeEquivalenceClass::RootOrAdminElevation);
        assert!(cmd_zero.is_cross_boundary);

        let cmd_delegated = parse_semantic_command("wsl --user guest whoami");
        assert_eq!(cmd_delegated.privilege_class, PrivilegeEquivalenceClass::TargetUserDelegation);
        assert!(cmd_delegated.is_cross_boundary);
        assert_eq!(cmd_delegated.target_user.as_deref(), Some("guest"));

        let cmd_query = parse_semantic_command("wsl -l -v");
        assert_eq!(cmd_query.privilege_class, PrivilegeEquivalenceClass::PrivilegeQueryOrBenign);
        assert!(cmd_query.is_cross_boundary);
    }

    #[test]
    fn test_runas_and_doas_and_su() {
        let cmd_runas = parse_semantic_command("runas /user:Administrator cmd.exe");
        assert_eq!(cmd_runas.privilege_class, PrivilegeEquivalenceClass::RootOrAdminElevation);
        assert_eq!(cmd_runas.target_user.as_deref(), Some("Administrator"));

        let cmd_runas_user = parse_semantic_command("runas /user:alice explorer.exe");
        assert_eq!(cmd_runas_user.privilege_class, PrivilegeEquivalenceClass::TargetUserDelegation);
        assert_eq!(cmd_runas_user.target_user.as_deref(), Some("alice"));

        let cmd_su_root = parse_semantic_command("su -");
        assert_eq!(cmd_su_root.privilege_class, PrivilegeEquivalenceClass::RootOrAdminElevation);

        let cmd_su_user = parse_semantic_command("su bob");
        assert_eq!(cmd_su_user.privilege_class, PrivilegeEquivalenceClass::TargetUserDelegation);
        assert_eq!(cmd_su_user.target_user.as_deref(), Some("bob"));

        let cmd_doas = parse_semantic_command("doas rm -rf /tmp/data");
        assert_eq!(cmd_doas.privilege_class, PrivilegeEquivalenceClass::RootOrAdminElevation);

        let cmd_pkexec = parse_semantic_command("pkexec sh");
        assert_eq!(cmd_pkexec.privilege_class, PrivilegeEquivalenceClass::RootOrAdminElevation);

        let cmd_pkexec_ver = parse_semantic_command("pkexec --version");
        assert_eq!(cmd_pkexec_ver.privilege_class, PrivilegeEquivalenceClass::PrivilegeQueryOrBenign);
    }

    #[test]
    fn test_shell_unwrapping_and_env_prefixes() {
        let cmd_wrapped = parse_semantic_command("bash -c \"sudo id\"");
        assert_eq!(cmd_wrapped.privilege_class, PrivilegeEquivalenceClass::RootOrAdminElevation);
        assert_eq!(cmd_wrapped.executable, "sudo");

        let cmd_env = parse_semantic_command("SUDO_ASKPASS=/bin/false VAR=val sudo -n id");
        assert_eq!(cmd_env.privilege_class, PrivilegeEquivalenceClass::RootOrAdminElevation);
        assert_eq!(cmd_env.executable, "sudo");
        assert_eq!(cmd_env.env_vars.len(), 2);
        assert!(cmd_env.is_non_interactive);
    }

    #[test]
    fn test_dynamic_probe_renamed_executable() {
        // Probe simulates an executable renamed to "/tmp/innocent_tool" that has SUID root set
        let probe = DynamicBinaryMetadataProbe::from_posix(0o104755, 0, 0);
        let cmd = parse_semantic_command_with_probe("/tmp/innocent_tool whoami", Some(&probe));
        assert_eq!(cmd.privilege_class, PrivilegeEquivalenceClass::RootOrAdminElevation);
        assert!(cmd.privilege_class.is_privileged_execution());

        // Probe simulates a Windows binary with requireAdministrator PE manifest
        let manifest = r#"<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>"#;
        let pe_probe = DynamicBinaryMetadataProbe::from_pe_manifest(manifest, &["kernel32.dll"]);
        let cmd_pe = parse_semantic_command_with_probe("custom_installer.exe /S", Some(&pe_probe));
        assert_eq!(cmd_pe.privilege_class, PrivilegeEquivalenceClass::RootOrAdminElevation);
    }

    #[test]
    fn test_unprivileged_standard_commands() {
        let cmd_cat = parse_semantic_command("cat /tmp/test.txt");
        assert_eq!(cmd_cat.privilege_class, PrivilegeEquivalenceClass::UnprivilegedStandard);
        assert!(!cmd_cat.privilege_class.is_privileged_execution());

        let cmd_git = parse_semantic_command("git status");
        assert_eq!(cmd_git.privilege_class, PrivilegeEquivalenceClass::UnprivilegedStandard);
    }
}
