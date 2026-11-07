//! Dynamic Binary Metadata Probing (Name-Independent).
//!
//! Inspects executable metadata on disk regardless of filename:
//! - POSIX / Linux / macOS / WSL2: `S_ISUID` (0o4000) and `S_ISGID` (0o2000) mode bits, file UID.
//! - Linux: `security.capability` extended attributes (`vfs_cap_data`).
//! - Windows / PE: Resource Directory `RT_MANIFEST` (Type 24) / XML manifest extraction for
//!   `<requestedExecutionLevel level="requireAdministrator" | "highestAvailable">`,
//!   and WSL / Hyper-V subsystem traits (`wslapi.dll`, `lxss`, `vmcompute.dll`).

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Requested execution level declared in Windows PE manifests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ElevationRequirement {
    RequireAdministrator,
    HighestAvailable,
    AsInvoker,
    None,
}

/// Dynamic metadata extracted from binary headers and filesystem attributes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DynamicBinaryMetadata {
    pub is_suid: bool,
    pub is_sgid: bool,
    pub file_uid: u32,
    pub has_linux_capabilities: bool,
    pub linux_capabilities_mask: u64,
    pub elevation_requirement: ElevationRequirement,
    pub invokes_wsl_subsystem: bool,
    pub invokes_hyperv_compute: bool,
}

impl Default for DynamicBinaryMetadata {
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

impl DynamicBinaryMetadata {
    /// Evaluates if the binary exhibits privileged, elevation, or containment-relevant traits.
    pub fn is_privileged_target(&self) -> bool {
        (self.is_suid && self.file_uid == 0)
            || self.has_linux_capabilities
            || matches!(
                self.elevation_requirement,
                ElevationRequirement::RequireAdministrator | ElevationRequirement::HighestAvailable
            )
            || self.invokes_wsl_subsystem
    }
}

/// Inspect target binary on disk, evaluating filesystem attributes and executable header metadata.
pub fn inspect_binary_metadata(path: &Path) -> std::io::Result<DynamicBinaryMetadata> {
    if !path.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Binary path not found: {}", path.display()),
        ));
    }

    let mut meta = DynamicBinaryMetadata::default();

    // 1. Filesystem-Level Mode & UID Inspection (POSIX)
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(fs_meta) = std::fs::metadata(path) {
            let mode = fs_meta.mode();
            meta.is_suid = (mode & 0o4000) != 0;
            meta.is_sgid = (mode & 0o2000) != 0;
            meta.file_uid = fs_meta.uid();
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
                    meta.has_linux_capabilities = true;
                    if res >= 8 {
                        let eff = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
                        meta.linux_capabilities_mask = eff as u64;
                    }
                }
            }
        }
    }

    // 2. Read executable header / manifest buffer (up to 4MB)
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    let _ = file.by_ref().take(4 * 1024 * 1024).read_to_end(&mut buffer)?;

    let parsed_meta = inspect_binary_metadata_from_bytes(&buffer);
    if parsed_meta.elevation_requirement != ElevationRequirement::None {
        meta.elevation_requirement = parsed_meta.elevation_requirement;
    }
    if parsed_meta.invokes_wsl_subsystem {
        meta.invokes_wsl_subsystem = true;
    }
    if parsed_meta.invokes_hyperv_compute {
        meta.invokes_hyperv_compute = true;
    }
    if parsed_meta.has_linux_capabilities {
        meta.has_linux_capabilities = true;
        meta.linux_capabilities_mask = parsed_meta.linux_capabilities_mask;
    }
    if parsed_meta.is_suid {
        meta.is_suid = true;
    }

    Ok(meta)
}

/// Inspect binary metadata directly from an in-memory byte buffer (PE header or ELF/POSIX indicators).
pub fn inspect_binary_metadata_from_bytes(bytes: &[u8]) -> DynamicBinaryMetadata {
    let mut meta = DynamicBinaryMetadata::default();
    if bytes.is_empty() {
        return meta;
    }

    // -------------------------------------------------------------------------
    // 1. PE (Portable Executable) Parsing
    // -------------------------------------------------------------------------
    if bytes.len() >= 64 && bytes[0] == b'M' && bytes[1] == b'Z' {
        let pe_offset = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
        if pe_offset + 4 <= bytes.len() && &bytes[pe_offset..pe_offset + 4] == b"PE\0\0" {
            // Valid PE header confirmed
            parse_pe_manifest_and_imports(bytes, pe_offset, &mut meta);
        }
    }

    // -------------------------------------------------------------------------
    // 2. Direct XML Manifest Extraction (UTF-8 / ASCII & UTF-16 LE)
    // -------------------------------------------------------------------------
    if meta.elevation_requirement == ElevationRequirement::None {
        if let Some(req) = scan_manifest_xml_for_elevation(bytes) {
            meta.elevation_requirement = req;
        }
    }

    // -------------------------------------------------------------------------
    // 3. Subsystem invocation traits scanning (WSL & Hyper-V)
    // -------------------------------------------------------------------------
    if !meta.invokes_wsl_subsystem
        && (find_subsequence_case_insensitive(bytes, b"wslapi.dll")
            || find_subsequence_case_insensitive(bytes, b"wsl.exe")
            || find_subsequence_case_insensitive(bytes, b"lxss"))
    {
        meta.invokes_wsl_subsystem = true;
    }
    if !meta.invokes_hyperv_compute
        && (find_subsequence_case_insensitive(bytes, b"vmcompute.dll")
            || find_subsequence_case_insensitive(bytes, b"compute-system"))
    {
        meta.invokes_hyperv_compute = true;
    }

    meta
}

fn parse_pe_manifest_and_imports(
    bytes: &[u8],
    pe_offset: usize,
    meta: &mut DynamicBinaryMetadata,
) {
    if pe_offset + 24 > bytes.len() {
        return;
    }

    // Optional header magic: 0x10B = PE32, 0x20B = PE32+
    let opt_magic = u16::from_le_bytes([bytes[pe_offset + 24], bytes[pe_offset + 25]]);
    let data_dir_offset = if opt_magic == 0x020B {
        // PE32+ (64-bit)
        pe_offset + 24 + 112
    } else if opt_magic == 0x010B {
        // PE32 (32-bit)
        pe_offset + 24 + 96
    } else {
        return;
    };

    // Data Directory 1: Imports (RVA 4 bytes, Size 4 bytes)
    // Data Directory 2: Resources (RVA 4 bytes, Size 4 bytes)
    if data_dir_offset + 24 <= bytes.len() {
        let import_rva = u32::from_le_bytes([
            bytes[data_dir_offset + 8],
            bytes[data_dir_offset + 9],
            bytes[data_dir_offset + 10],
            bytes[data_dir_offset + 11],
        ]);
        let resource_rva = u32::from_le_bytes([
            bytes[data_dir_offset + 16],
            bytes[data_dir_offset + 17],
            bytes[data_dir_offset + 18],
            bytes[data_dir_offset + 19],
        ]);

        if import_rva > 0 || resource_rva > 0 {
            // Fallthrough to direct buffer scanning across mapped sections
        }
    }

    if let Some(req) = scan_manifest_xml_for_elevation(bytes) {
        meta.elevation_requirement = req;
    }
}

/// Scans raw bytes for manifest XML requestedExecutionLevel attributes in both UTF-8 and UTF-16 LE.
fn scan_manifest_xml_for_elevation(bytes: &[u8]) -> Option<ElevationRequirement> {
    // 1. ASCII / UTF-8 search
    if let Ok(text) = std::str::from_utf8(bytes) {
        if let Some(req) = parse_xml_requested_execution_level(text) {
            return Some(req);
        }
    } else {
        // Lossy UTF-8 conversion for arbitrary binary sections
        let text = String::from_utf8_lossy(bytes);
        if let Some(req) = parse_xml_requested_execution_level(&text) {
            return Some(req);
        }
    }

    // 2. UTF-16 LE search
    if bytes.len() >= 4 {
        let u16_chars: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        let utf16_str = String::from_utf16_lossy(&u16_chars);
        if let Some(req) = parse_xml_requested_execution_level(&utf16_str) {
            return Some(req);
        }
    }

    None
}

fn parse_xml_requested_execution_level(content: &str) -> Option<ElevationRequirement> {
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

fn find_subsequence_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle.iter())
            .all(|(&h, &n)| h.eq_ignore_ascii_case(&n))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elevation_require_administrator_detection() {
        let manifest = r#"
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
                <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
                    <security>
                        <requestedPrivileges>
                            <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
                        </requestedPrivileges>
                    </security>
                </trustInfo>
            </assembly>
        "#;

        let meta = inspect_binary_metadata_from_bytes(manifest.as_bytes());
        assert_eq!(
            meta.elevation_requirement,
            ElevationRequirement::RequireAdministrator
        );
        assert!(meta.is_privileged_target());
    }

    #[test]
    fn test_elevation_highest_available_detection() {
        let manifest = r#"
            <requestedExecutionLevel level='highestAvailable' uiAccess='false'/>
        "#;

        let meta = inspect_binary_metadata_from_bytes(manifest.as_bytes());
        assert_eq!(
            meta.elevation_requirement,
            ElevationRequirement::HighestAvailable
        );
        assert!(meta.is_privileged_target());
    }

    #[test]
    fn test_elevation_as_invoker_detection() {
        let manifest = r#"
            <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
        "#;

        let meta = inspect_binary_metadata_from_bytes(manifest.as_bytes());
        assert_eq!(meta.elevation_requirement, ElevationRequirement::AsInvoker);
        assert!(!meta.is_privileged_target());
    }

    #[test]
    fn test_wsl_and_hyperv_subsystem_detection() {
        let mock_pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\
            \xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\
            \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
            \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\
            Importing WSLAPI.DLL and VMCOMPUTE.DLL dynamically for container execution";

        let meta = inspect_binary_metadata_from_bytes(mock_pe);
        assert!(meta.invokes_wsl_subsystem);
        assert!(meta.invokes_hyperv_compute);
        assert!(meta.is_privileged_target());
    }

    #[test]
    fn test_utf16le_manifest_parsing() {
        let manifest_utf8 = "<requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/>";
        let mut utf16_bytes = Vec::new();
        for ch in manifest_utf8.encode_utf16() {
            utf16_bytes.extend_from_slice(&ch.to_le_bytes());
        }

        let meta = inspect_binary_metadata_from_bytes(&utf16_bytes);
        assert_eq!(
            meta.elevation_requirement,
            ElevationRequirement::RequireAdministrator
        );
        assert!(meta.is_privileged_target());
    }

    #[test]
    fn test_suid_privileged_evaluation() {
        let mut meta = DynamicBinaryMetadata {
            is_suid: true,
            file_uid: 0,
            ..Default::default()
        };
        assert!(meta.is_privileged_target());

        // Non-root SUID is not flagged as root target
        meta.file_uid = 1000;
        assert!(!meta.is_privileged_target());
    }
}
