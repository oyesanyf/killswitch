//! Windows host kernel discovery using dynamic `ntdll!RtlGetVersion` and registry inspection.

#[cfg(windows)]
use crate::cpe::{canonicalize_windows_cpe, Cpe23};
use crate::error::PatcherError;
use crate::types::HostKernelInfo;
#[cfg(windows)]
use crate::types::OsFamily;

#[cfg(windows)]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_snake_case)]
pub struct OSVERSIONINFOEXW {
    pub dwOSVersionInfoSize: u32,
    pub dwMajorVersion: u32,
    pub dwMinorVersion: u32,
    pub dwBuildNumber: u32,
    pub dwPlatformId: u32,
    pub szCSDVersion: [u16; 128],
    pub wServicePackMajor: u16,
    pub wServicePackMinor: u16,
    pub wSuiteMask: u16,
    pub wProductType: u8,
    pub wReserved: u8,
}

#[cfg(windows)]
type RtlGetVersionFn = unsafe extern "system" fn(*mut OSVERSIONINFOEXW) -> i32;

/// Raw NT kernel version fields extracted via `RtlGetVersion`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawNtVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub is_workstation: bool,
}

#[cfg(windows)]
pub fn query_ntdll_rtl_get_version() -> Result<RawNtVersion, PatcherError> {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    unsafe {
        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr() as *const u8);
        if ntdll.is_null() {
            return Err(PatcherError::DetectionFailed(
                "ntdll.dll module handle not found".into(),
            ));
        }
        let proc = GetProcAddress(ntdll, c"RtlGetVersion".as_ptr() as *const u8);
        let Some(proc) = proc else {
            return Err(PatcherError::DetectionFailed(
                "RtlGetVersion symbol not found in ntdll.dll".into(),
            ));
        };
        let rtl_get_version: RtlGetVersionFn = std::mem::transmute(proc);

        let mut os_info: OSVERSIONINFOEXW = std::mem::zeroed();
        os_info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;

        let status = rtl_get_version(&mut os_info);
        if status != 0 {
            return Err(PatcherError::DetectionFailed(format!(
                "RtlGetVersion failed with NTSTATUS 0x{status:08X}"
            )));
        }

        Ok(RawNtVersion {
            major: os_info.dwMajorVersion,
            minor: os_info.dwMinorVersion,
            build: os_info.dwBuildNumber,
            is_workstation: os_info.wProductType == 1,
        })
    }
}

/// Registry metadata read from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WindowsRegistryInfo {
    pub ubr: Option<u32>,
    pub display_version: Option<String>,
    pub product_name: Option<String>,
    pub edition_id: Option<String>,
    pub installation_type: Option<String>,
}

#[cfg(windows)]
pub fn query_windows_registry() -> WindowsRegistryInfo {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");

    match key {
        Ok(k) => {
            let ubr: Option<u32> = k.get_value("UBR").ok();
            let display_version: Option<String> = k
                .get_value("DisplayVersion")
                .or_else(|_| k.get_value("ReleaseId"))
                .ok();
            let product_name: Option<String> = k.get_value("ProductName").ok();
            let edition_id: Option<String> = k.get_value("EditionID").ok();
            let installation_type: Option<String> = k.get_value("InstallationType").ok();
            WindowsRegistryInfo {
                ubr,
                display_version,
                product_name,
                edition_id,
                installation_type,
            }
        }
        Err(_) => WindowsRegistryInfo::default(),
    }
}

#[cfg(windows)]
pub fn detect_windows_kernel() -> Result<HostKernelInfo, PatcherError> {
    let raw = query_ntdll_rtl_get_version()?;
    let reg = query_windows_registry();

    let is_server = !raw.is_workstation
        || reg
            .installation_type
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("Server"))
            .unwrap_or(false);

    let (cpe_product, cpe_version) =
        canonicalize_windows_cpe(raw.build, is_server, reg.display_version.as_deref());
    let cpe = Cpe23::new_os("microsoft", cpe_product, cpe_version);
    let cpe23 = cpe.to_formatted_string();

    let kernel_release = match reg.ubr {
        Some(ubr) => format!("{}.{}.{}.{}", raw.major, raw.minor, raw.build, ubr),
        None => format!("{}.{}.{}", raw.major, raw.minor, raw.build),
    };

    let product_label = if is_server {
        if raw.build >= 26100 {
            "Windows Server 2025"
        } else if raw.build >= 20348 {
            "Windows Server 2022"
        } else if raw.build >= 17763 {
            "Windows Server 2019"
        } else if raw.build >= 14393 {
            "Windows Server 2016"
        } else {
            "Windows Server"
        }
    } else if raw.build >= 22000 {
        "Windows 11"
    } else if raw.build >= 10240 {
        "Windows 10"
    } else {
        "Windows"
    };

    let os_version = match (reg.product_name.as_deref(), reg.display_version.as_deref()) {
        (Some(p), Some(dv)) => format!("{p} {dv} (Build {kernel_release})"),
        (Some(p), None) => format!("{p} (Build {kernel_release})"),
        (None, Some(dv)) => format!("{product_label} {dv} (Build {kernel_release})"),
        (None, None) => format!("{product_label} (Build {kernel_release})"),
    };

    Ok(HostKernelInfo {
        os_family: OsFamily::Windows,
        kernel_release,
        os_version,
        cpe23,
        architecture: std::env::consts::ARCH.to_string(),
    })
}

#[cfg(not(windows))]
pub fn detect_windows_kernel() -> Result<HostKernelInfo, PatcherError> {
    Err(PatcherError::UnsupportedPlatform(
        "Windows detection invoked on non-Windows host".to_string(),
    ))
}
