//! Linux host kernel discovery via `/proc/sys/kernel/osrelease`, `/etc/os-release`, and `libc::uname`.

#[cfg(target_os = "linux")]
use crate::cpe::{canonicalize_linux_kernel_version, Cpe23};
use crate::error::PatcherError;
use crate::types::HostKernelInfo;
#[cfg(target_os = "linux")]
use crate::types::OsFamily;

/// Metadata parsed from `/etc/os-release` or `/usr/lib/os-release`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsRelease {
    pub id: String,
    pub version_id: String,
    pub pretty_name: String,
    pub id_like: Vec<String>,
}

/// Parses standard freedesktop.org `/etc/os-release` file content.
#[must_use]
pub fn parse_os_release_content(content: &str) -> OsRelease {
    let mut info = OsRelease::default();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let key = k.trim();
            let mut val = v.trim();
            if ((val.starts_with('"') && val.ends_with('"'))
                || (val.starts_with('\'') && val.ends_with('\'')))
                && val.len() >= 2
            {
                val = &val[1..val.len() - 1];
            }
            match key {
                "ID" => info.id = val.to_ascii_lowercase(),
                "VERSION_ID" => info.version_id = val.to_string(),
                "PRETTY_NAME" => info.pretty_name = val.to_string(),
                "ID_LIKE" => {
                    info.id_like = val
                        .split_whitespace()
                        .map(|s| s.to_ascii_lowercase())
                        .collect();
                }
                _ => {}
            }
        }
    }
    info
}

#[cfg(target_os = "linux")]
pub fn detect_linux_os_release() -> OsRelease {
    use std::fs;
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        return parse_os_release_content(&content);
    }
    if let Ok(content) = fs::read_to_string("/usr/lib/os-release") {
        return parse_os_release_content(&content);
    }
    OsRelease::default()
}

#[cfg(target_os = "linux")]
pub fn detect_linux_kernel_release() -> Result<String, PatcherError> {
    use std::fs;
    if let Ok(content) = fs::read_to_string("/proc/sys/kernel/osrelease") {
        let release = content.trim().to_string();
        if !release.is_empty() {
            return Ok(release);
        }
    }

    // Fallback to libc::uname
    unsafe {
        let mut uts = std::mem::zeroed::<libc::utsname>();
        if libc::uname(&mut uts) != 0 {
            return Err(PatcherError::DetectionFailed(
                "uname syscall failed".to_string(),
            ));
        }
        let c_str = std::ffi::CStr::from_ptr(uts.release.as_ptr());
        let release = c_str.to_string_lossy().trim().to_string();
        if release.is_empty() {
            Err(PatcherError::DetectionFailed(
                "Empty kernel release returned by uname".to_string(),
            ))
        } else {
            Ok(release)
        }
    }
}

#[cfg(target_os = "linux")]
pub fn detect_linux_host_kernel() -> Result<HostKernelInfo, PatcherError> {
    let kernel_release = detect_linux_kernel_release()?;
    let os_release = detect_linux_os_release();
    let base_version = canonicalize_linux_kernel_version(&kernel_release);
    let cpe = Cpe23::new_os("linux", "linux_kernel", base_version);
    let cpe23 = cpe.to_formatted_string();

    let os_version = if !os_release.version_id.is_empty() {
        os_release.version_id
    } else if !os_release.pretty_name.is_empty() {
        os_release.pretty_name
    } else {
        "unknown".to_string()
    };

    Ok(HostKernelInfo {
        os_family: OsFamily::Linux,
        kernel_release,
        os_version,
        cpe23,
        architecture: std::env::consts::ARCH.to_string(),
    })
}

#[cfg(not(target_os = "linux"))]
pub fn detect_linux_host_kernel() -> Result<HostKernelInfo, PatcherError> {
    Err(PatcherError::UnsupportedPlatform(
        "Linux detection invoked on non-Linux host".to_string(),
    ))
}
