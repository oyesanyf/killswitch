//! macOS host kernel discovery using `libc::sysctlbyname`.

#[cfg(target_os = "macos")]
use crate::cpe::{canonicalize_macos_version, Cpe23};
use crate::error::PatcherError;
use crate::types::HostKernelInfo;
#[cfg(target_os = "macos")]
use crate::types::OsFamily;

#[cfg(target_os = "macos")]
pub fn sysctl_string(name: &str) -> Result<String, PatcherError> {
    use std::ffi::CString;
    use std::ptr;

    let c_name = CString::new(name)
        .map_err(|e| PatcherError::DetectionFailed(format!("Invalid sysctl name '{name}': {e}")))?;

    let mut size: libc::size_t = 0;
    let ret = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            ptr::null_mut(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if ret != 0 || size == 0 {
        return Err(PatcherError::DetectionFailed(format!(
            "sysctlbyname('{name}') failed to query size: errno={}",
            std::io::Error::last_os_error()
        )));
    }

    let mut buf = vec![0u8; size];
    let ret = unsafe {
        libc::sysctlbyname(
            c_name.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return Err(PatcherError::DetectionFailed(format!(
            "sysctlbyname('{name}') failed to retrieve value: errno={}",
            std::io::Error::last_os_error()
        )));
    }

    while buf.last() == Some(&0) {
        buf.pop();
    }
    String::from_utf8(buf).map_err(|e| {
        PatcherError::DetectionFailed(format!("sysctlbyname('{name}') returned non-UTF8: {e}"))
    })
}

#[cfg(target_os = "macos")]
pub fn detect_macos_host_kernel() -> Result<HostKernelInfo, PatcherError> {
    let kernel_release = sysctl_string("kern.osrelease")?;
    let os_version = sysctl_string("kern.osproductversion")
        .map(|v| canonicalize_macos_version(&v))
        .unwrap_or_else(|_| {
            // Darwin math fallback: Darwin 20+ -> macOS (Darwin - 9)
            if let Some(major) = kernel_release
                .split('.')
                .next()
                .and_then(|s| s.parse::<u32>().ok())
                .filter(|&m| m >= 20)
            {
                return format!("{}.0", major - 9);
            }
            "14.0".to_string()
        });

    let cpe = Cpe23::new_os("apple", "macos", &os_version);
    let cpe23 = cpe.to_formatted_string();

    Ok(HostKernelInfo {
        os_family: OsFamily::MacOS,
        kernel_release,
        os_version,
        cpe23,
        architecture: std::env::consts::ARCH.to_string(),
    })
}

#[cfg(not(target_os = "macos"))]
pub fn detect_macos_host_kernel() -> Result<HostKernelInfo, PatcherError> {
    Err(PatcherError::UnsupportedPlatform(
        "macOS detection invoked on non-macOS host".to_string(),
    ))
}
