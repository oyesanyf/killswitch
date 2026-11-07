//! Sensitive System Path & Credential Store Recognition Engine.
//!
//! Provides fail-closed identification and canonicalization of critical OS credential stores:
//! - Linux/Unix: /etc/shadow, /etc/gshadow, /etc/sudoers, /etc/sudoers.d/*, /etc/master.passwd, /etc/security/opasswd
//! - Windows: System32\config\SAM, System32\config\SYSTEM, System32\config\SECURITY, RegBack hives, and .LOG transaction files
//! - Active Directory: NTDS\ntds.dit
//! - Registry commands: HKLM\SAM, HKLM\SYSTEM, HKLM\SECURITY

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SensitiveCredentialStoreKind {
    UnixShadow,
    UnixGshadow,
    UnixSudoers,
    BsdMasterPasswd,
    UnixOpasswd,
    WindowsSamHive,
    WindowsSystemHive,
    WindowsSecurityHive,
    WindowsNtdsDit,
}

impl SensitiveCredentialStoreKind {
    pub fn description(&self) -> &'static str {
        match self {
            Self::UnixShadow => "Unix shadow password database (/etc/shadow)",
            Self::UnixGshadow => "Unix group shadow password database (/etc/gshadow)",
            Self::UnixSudoers => "Unix sudoers privilege configuration (/etc/sudoers)",
            Self::BsdMasterPasswd => "BSD/macOS master password database (/etc/master.passwd)",
            Self::UnixOpasswd => "Linux PAM previous password store (/etc/security/opasswd)",
            Self::WindowsSamHive => "Windows SAM registry hive (System32\\config\\SAM)",
            Self::WindowsSystemHive => "Windows SYSTEM registry hive (System32\\config\\SYSTEM)",
            Self::WindowsSecurityHive => "Windows SECURITY registry hive (System32\\config\\SECURITY)",
            Self::WindowsNtdsDit => "Windows Active Directory database (NTDS\\ntds.dit)",
        }
    }
}

/// Normalizes and canonicalizes a path for security inspection.
pub fn normalize_path_for_inspection(raw: &str) -> String {
    let s = raw.trim().trim_matches(['"', '\'', '`']);
    if s.is_empty() {
        return String::new();
    }

    // 1. Percent-decode %2f, %5c, %2e, %00
    let mut decoded = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            let h1 = chars.next();
            let h2 = chars.next();
            if let (Some(c1), Some(c2)) = (h1, h2) {
                let hex_str = format!("{}{}", c1, c2);
                if let Ok(byte) = u8::from_str_radix(&hex_str, 16) {
                    match byte {
                        b'/' | b'\\' => decoded.push('/'),
                        b'.' => decoded.push('.'),
                        0 => {} // Strip null byte
                        _ => {
                            decoded.push('%');
                            decoded.push(c1);
                            decoded.push(c2);
                        }
                    }
                    continue;
                }
                decoded.push('%');
                decoded.push(c1);
                decoded.push(c2);
            } else {
                decoded.push('%');
                if let Some(c1) = h1 {
                    decoded.push(c1);
                }
            }
        } else {
            decoded.push(c);
        }
    }

    // 2. Normalize separators to '/' and convert to lowercase
    let mut lower = decoded.replace('\\', "/").to_ascii_lowercase();

    // 3. Strip Windows device / namespace prefixes
    for prefix in &["//?/", "//./", "/??/", "/device/"] {
        if lower.starts_with(prefix) {
            lower = lower[prefix.len()..].to_string();
            break;
        }
    }

    // 4. Strip Windows drive letters (e.g. C:, D:)
    if lower.len() >= 2 && lower.as_bytes()[0].is_ascii_alphabetic() && lower.as_bytes()[1] == b':' {
        lower = lower[2..].to_string();
    }

    // 5. Strip WSL2 / Git Bash mount prefixes (e.g. /mnt/c/, /c/)
    if lower.starts_with("/mnt/") && lower.len() >= 7 && lower.as_bytes()[6] == b'/' {
        lower = lower[6..].to_string();
    } else if lower.starts_with("/cygdrive/") && lower.len() >= 12 && lower.as_bytes()[11] == b'/' {
        lower = lower[11..].to_string();
    } else if lower.len() >= 3 && lower.starts_with('/') && lower.as_bytes()[1].is_ascii_alphabetic() && lower.as_bytes()[2] == b'/' {
        lower = lower[2..].to_string();
    }

    // 6. Strip NTFS Alternate Data Stream suffixes (::$DATA, :stream)
    if let Some(colon_pos) = lower.find(':') {
        lower.truncate(colon_pos);
    }

    // 7. Resolve '.' and '..' segments
    let segments: Vec<&str> = lower.split('/').collect();
    let mut resolved: Vec<&str> = Vec::new();
    let is_absolute = lower.starts_with('/');

    for seg in segments {
        let seg_clean = seg.trim();
        if seg_clean.is_empty() || seg_clean == "." {
            continue;
        }
        if seg_clean == ".." {
            resolved.pop();
        } else {
            resolved.push(seg_clean);
        }
    }

    let joined = resolved.join("/");
    if is_absolute {
        format!("/{}", joined)
    } else {
        joined
    }
}

/// Classifies whether a path points to a sensitive credential store.
pub fn classify_sensitive_system_path(raw_path: &str) -> Option<SensitiveCredentialStoreKind> {
    let norm = normalize_path_for_inspection(raw_path);
    if norm.is_empty() {
        return None;
    }

    let stripped = norm.strip_prefix('/').unwrap_or(&norm);

    // 1. Linux/Unix shadow
    if stripped == "etc/shadow"
        || stripped.starts_with("etc/shadow-")
        || stripped.starts_with("etc/shadow.")
        || stripped == "etc/shadow~"
        || stripped.starts_with("var/backups/shadow")
    {
        return Some(SensitiveCredentialStoreKind::UnixShadow);
    }

    // 2. Linux/Unix gshadow
    if stripped == "etc/gshadow"
        || stripped.starts_with("etc/gshadow-")
        || stripped.starts_with("etc/gshadow.")
        || stripped == "etc/gshadow~"
        || stripped.starts_with("var/backups/gshadow")
    {
        return Some(SensitiveCredentialStoreKind::UnixGshadow);
    }

    // 3. Linux/Unix sudoers
    if stripped == "etc/sudoers"
        || stripped.starts_with("etc/sudoers.")
        || stripped == "etc/sudoers~"
        || stripped == "etc/sudoers.d"
        || stripped.starts_with("etc/sudoers.d/")
    {
        return Some(SensitiveCredentialStoreKind::UnixSudoers);
    }

    // 4. BSD / macOS master.passwd
    if stripped == "etc/master.passwd" || stripped.starts_with("etc/master.passwd.") {
        return Some(SensitiveCredentialStoreKind::BsdMasterPasswd);
    }

    // 5. PAM opasswd
    if stripped == "etc/security/opasswd" || stripped.starts_with("etc/security/opasswd.") {
        return Some(SensitiveCredentialStoreKind::UnixOpasswd);
    }

    // 6. Windows SAM hive
    if is_windows_hive_match(stripped, "sam") || is_registry_key_match(raw_path, "sam") {
        return Some(SensitiveCredentialStoreKind::WindowsSamHive);
    }

    // 7. Windows SYSTEM hive
    if is_windows_hive_match(stripped, "system") || is_registry_key_match(raw_path, "system") {
        return Some(SensitiveCredentialStoreKind::WindowsSystemHive);
    }

    // 8. Windows SECURITY hive
    if is_windows_hive_match(stripped, "security") || is_registry_key_match(raw_path, "security") {
        return Some(SensitiveCredentialStoreKind::WindowsSecurityHive);
    }

    // 9. Windows NTDS database
    if stripped.ends_with("ntds/ntds.dit") || stripped == "ntds.dit" {
        return Some(SensitiveCredentialStoreKind::WindowsNtdsDit);
    }

    None
}

fn is_windows_hive_match(stripped: &str, hive_name: &str) -> bool {
    let candidate = if let Some(after_win) = stripped.strip_prefix("windows/") {
        after_win
    } else if let Some(after_winnt) = stripped.strip_prefix("winnt/") {
        after_winnt
    } else {
        stripped
    };

    let tail = if let Some(t) = candidate.strip_prefix("system32/config/regback/") {
        t
    } else if let Some(t) = candidate.strip_prefix("system32/config/") {
        t
    } else {
        return false;
    };

    if tail == hive_name {
        return true;
    }

    if let Some(stem) = tail.strip_prefix(hive_name) {
        if stem.starts_with('.') || stem.starts_with('~') {
            return true;
        }
    }

    false
}

fn is_registry_key_match(raw: &str, hive_name: &str) -> bool {
    let lower = raw.trim().to_ascii_lowercase().replace('/', "\\");
    for prefix in &["hklm\\", "hkey_local_machine\\"] {
        if let Some(after) = lower.strip_prefix(prefix) {
            let key = after.split('\\').next().unwrap_or("");
            if key == hive_name {
                return true;
            }
        }
    }
    false
}

/// Scans arbitrary text (such as command strings) for sensitive system paths.
pub fn scan_for_sensitive_system_path(text: &str) -> Option<(SensitiveCredentialStoreKind, String)> {
    let tokens = crate::semantic_command::tokenize_command(text);
    for tok in tokens {
        let clean = tok.trim_matches(['"', '\'', '(', ')', '[', ']', '{', '}', ';', ',']);
        if let Some(kind) = classify_sensitive_system_path(clean) {
            return Some((kind, clean.to_string()));
        }
    }

    // Substring fallback for embedded arguments (e.g. open('/etc/shadow'))
    let lower = text.to_ascii_lowercase().replace('\\', "/");
    let targets = [
        ("etc/shadow", SensitiveCredentialStoreKind::UnixShadow),
        ("etc/gshadow", SensitiveCredentialStoreKind::UnixGshadow),
        ("etc/sudoers", SensitiveCredentialStoreKind::UnixSudoers),
        ("etc/master.passwd", SensitiveCredentialStoreKind::BsdMasterPasswd),
        ("system32/config/sam", SensitiveCredentialStoreKind::WindowsSamHive),
        ("system32/config/system", SensitiveCredentialStoreKind::WindowsSystemHive),
        ("system32/config/security", SensitiveCredentialStoreKind::WindowsSecurityHive),
        ("hklm\\sam", SensitiveCredentialStoreKind::WindowsSamHive),
        ("hklm\\system", SensitiveCredentialStoreKind::WindowsSystemHive),
        ("hklm\\security", SensitiveCredentialStoreKind::WindowsSecurityHive),
    ];

    for (needle, kind) in targets {
        if lower.contains(needle) {
            return Some((kind, needle.to_string()));
        }
    }

    None
}

/// Recursively scans a serde_json::Value for sensitive system paths.
pub fn scan_json_for_sensitive_path(val: &serde_json::Value) -> Option<(SensitiveCredentialStoreKind, String)> {
    match val {
        serde_json::Value::String(s) => {
            if let Some(kind) = classify_sensitive_system_path(s) {
                return Some((kind, s.clone()));
            }
            scan_for_sensitive_system_path(s)
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let Some(found) = scan_json_for_sensitive_path(item) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Object(map) => {
            for (_k, v) in map {
                if let Some(found) = scan_json_for_sensitive_path(v) {
                    return Some(found);
                }
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path_basic() {
        assert_eq!(normalize_path_for_inspection("/etc/shadow"), "/etc/shadow");
        assert_eq!(normalize_path_for_inspection("\\etc\\shadow"), "/etc/shadow");
        assert_eq!(normalize_path_for_inspection("/etc//shadow"), "/etc/shadow");
        assert_eq!(normalize_path_for_inspection("C:\\Windows\\System32\\config\\SAM"), "/windows/system32/config/sam");
    }

    #[test]
    fn test_normalize_path_traversal() {
        assert_eq!(normalize_path_for_inspection("/var/tmp/../../etc/shadow"), "/etc/shadow");
        assert_eq!(
            normalize_path_for_inspection("C:\\Windows\\System32\\drivers\\..\\config\\SAM"),
            "/windows/system32/config/sam"
        );
    }

    #[test]
    fn test_normalize_percent_encoding() {
        assert_eq!(normalize_path_for_inspection("%2fetc%2fshadow"), "/etc/shadow");
        assert_eq!(normalize_path_for_inspection("..%2f..%2fetc%2fshadow"), "etc/shadow");
    }

    #[test]
    fn test_normalize_ads_stripping() {
        assert_eq!(
            normalize_path_for_inspection("C:\\Windows\\System32\\config\\SAM::$DATA"),
            "/windows/system32/config/sam"
        );
    }

    #[test]
    fn test_classify_sensitive_system_paths() {
        assert_eq!(
            classify_sensitive_system_path("/etc/shadow"),
            Some(SensitiveCredentialStoreKind::UnixShadow)
        );
        assert_eq!(
            classify_sensitive_system_path("/etc/shadow.bak"),
            Some(SensitiveCredentialStoreKind::UnixShadow)
        );
        assert_eq!(
            classify_sensitive_system_path("/etc/sudoers"),
            Some(SensitiveCredentialStoreKind::UnixSudoers)
        );
        assert_eq!(
            classify_sensitive_system_path("/etc/sudoers.d/90-admin"),
            Some(SensitiveCredentialStoreKind::UnixSudoers)
        );
        assert_eq!(
            classify_sensitive_system_path("C:\\Windows\\System32\\config\\SAM"),
            Some(SensitiveCredentialStoreKind::WindowsSamHive)
        );
        assert_eq!(
            classify_sensitive_system_path("C:\\Windows\\System32\\config\\RegBack\\SYSTEM"),
            Some(SensitiveCredentialStoreKind::WindowsSystemHive)
        );
        assert_eq!(
            classify_sensitive_system_path("HKLM\\SAM"),
            Some(SensitiveCredentialStoreKind::WindowsSamHive)
        );
        assert_eq!(
            classify_sensitive_system_path("/var/log/normal.txt"),
            None
        );
    }

    #[test]
    fn test_scan_for_sensitive_paths_in_commands() {
        assert!(scan_for_sensitive_system_path("cat /etc/shadow").is_some());
        assert!(scan_for_sensitive_system_path("type C:\\Windows\\System32\\config\\SAM").is_some());
        assert!(scan_for_sensitive_system_path("python -c \"open('/etc/sudoers')\"").is_some());
        assert!(scan_for_sensitive_system_path("git status").is_none());
    }

    #[test]
    fn test_scan_json_for_sensitive_path() {
        let v = serde_json::json!({
            "tool": "read_file",
            "params": {
                "path": "/etc/shadow"
            }
        });
        assert!(scan_json_for_sensitive_path(&v).is_some());

        let clean = serde_json::json!({
            "tool": "read_file",
            "params": {
                "path": "/workspace/main.rs"
            }
        });
        assert!(scan_json_for_sensitive_path(&clean).is_none());
    }
}
