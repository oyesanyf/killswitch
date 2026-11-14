//! Privilege elevation verification.

/// Returns `true` if the calling process possesses elevated administrative / root privileges.
/// Enforces fail-closed semantics: returns `false` on any OS API failure or error.
#[must_use]
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        windows::is_current_process_elevated()
    }
    #[cfg(unix)]
    {
        unix::is_current_process_elevated()
    }
    #[cfg(not(any(windows, unix)))]
    {
        false
    }
}

#[cfg(unix)]
pub mod unix {
    /// Checks if the effective UID of the current process is root (0).
    ///
    /// Safety: `libc::geteuid()` is an infallible, stateless POSIX syscall.
    #[inline]
    #[must_use]
    pub fn is_current_process_elevated() -> bool {
        unsafe { libc::geteuid() == 0 }
    }
}

#[cfg(windows)]
pub mod windows {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// Checks if the current process token has elevated privileges (`TokenElevation`).
    /// Fails closed and returns `false` on any Win32 API failure.
    #[must_use]
    pub fn is_current_process_elevated() -> bool {
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut return_length: u32 = 0;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut core::ffi::c_void,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }
}
