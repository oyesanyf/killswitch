//! Host operating system and kernel discovery.

pub mod linux;
pub mod macos;
pub mod windows;

use crate::cpe::{
    canonicalize_linux_kernel_version, canonicalize_macos_version, canonicalize_windows_cpe, Cpe23,
};
use crate::error::PatcherError;
use crate::types::{HostKernelInfo, OsFamily};

/// Returns the compile-time host CPU architecture.
#[inline]
#[must_use]
pub fn detect_architecture() -> String {
    std::env::consts::ARCH.to_string()
}

/// Dispatches kernel detection to the current operating system platform.
pub fn detect_host_kernel() -> Result<HostKernelInfo, PatcherError> {
    #[cfg(target_os = "windows")]
    {
        windows::detect_windows_kernel()
    }
    #[cfg(target_os = "linux")]
    {
        linux::detect_linux_host_kernel()
    }
    #[cfg(target_os = "macos")]
    {
        macos::detect_macos_host_kernel()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Err(PatcherError::UnsupportedPlatform(
            std::env::consts::OS.to_string(),
        ))
    }
}

/// Pure parser for Linux kernel discovery metadata (decoupled for testing).
#[must_use]
pub fn parse_linux_kernel_info(
    kernel_release: &str,
    os_release_content: Option<&str>,
    arch: &str,
) -> HostKernelInfo {
    let os_release = os_release_content
        .map(linux::parse_os_release_content)
        .unwrap_or_default();

    let base_version = canonicalize_linux_kernel_version(kernel_release);
    let cpe = Cpe23::new_os("linux", "linux_kernel", base_version);
    let cpe23 = cpe.to_formatted_string();

    let os_version = if !os_release.version_id.is_empty() {
        os_release.version_id
    } else if !os_release.pretty_name.is_empty() {
        os_release.pretty_name
    } else {
        "unknown".to_string()
    };

    HostKernelInfo {
        os_family: OsFamily::Linux,
        kernel_release: kernel_release.trim().to_string(),
        os_version,
        cpe23,
        architecture: arch.to_string(),
    }
}

/// Pure parser for Windows kernel discovery metadata (decoupled for testing).
#[must_use]
pub fn parse_windows_kernel_info(
    major: u32,
    minor: u32,
    build: u32,
    ubr: Option<u32>,
    product_name: Option<&str>,
    display_version: Option<&str>,
    arch: &str,
) -> HostKernelInfo {
    let is_server = product_name
        .map(|p| p.to_ascii_lowercase().contains("server"))
        .unwrap_or(false);

    let (cpe_product, cpe_version) = canonicalize_windows_cpe(build, is_server, display_version);
    let cpe = Cpe23::new_os("microsoft", cpe_product, cpe_version);
    let cpe23 = cpe.to_formatted_string();

    let kernel_release = match ubr {
        Some(u) => format!("{major}.{minor}.{build}.{u}"),
        None => format!("{major}.{minor}.{build}"),
    };

    let os_version = match (product_name, display_version) {
        (Some(p), Some(dv)) => format!("{p} {dv} (Build {kernel_release})"),
        (Some(p), None) => format!("{p} (Build {kernel_release})"),
        (None, Some(dv)) => {
            let label = if is_server {
                "Windows Server"
            } else if build >= 22000 {
                "Windows 11"
            } else {
                "Windows 10"
            };
            format!("{label} {dv} (Build {kernel_release})")
        }
        (None, None) => {
            let label = if is_server {
                "Windows Server"
            } else if build >= 22000 {
                "Windows 11"
            } else {
                "Windows 10"
            };
            format!("{label} (Build {kernel_release})")
        }
    };

    HostKernelInfo {
        os_family: OsFamily::Windows,
        kernel_release,
        os_version,
        cpe23,
        architecture: arch.to_string(),
    }
}

/// Pure parser for macOS kernel discovery metadata (decoupled for testing).
#[must_use]
pub fn parse_macos_kernel_info(
    os_product_version: Option<&str>,
    kernel_release: &str,
    arch: &str,
) -> HostKernelInfo {
    let os_version = os_product_version
        .map(canonicalize_macos_version)
        .unwrap_or_else(|| {
            if let Some(major_str) = kernel_release.split('.').next() {
                if let Ok(major) = major_str.parse::<u32>() {
                    if major >= 20 {
                        return format!("{}.0", major - 9);
                    }
                }
            }
            "14.0".to_string()
        });

    let cpe = Cpe23::new_os("apple", "macos", &os_version);
    let cpe23 = cpe.to_formatted_string();

    HostKernelInfo {
        os_family: OsFamily::MacOS,
        kernel_release: kernel_release.trim().to_string(),
        os_version,
        cpe23,
        architecture: arch.to_string(),
    }
}
