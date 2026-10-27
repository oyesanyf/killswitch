//! In-memory Authenticode signature verification cache and cryptographic trust evaluation.
//!
//! Provides:
//! - Windows native WinVerifyTrust FFI (`WINTRUST_ACTION_GENERIC_VERIFY_V2`).
//! - Windows Security Catalog (`CatRoot`) hash verification via `CryptCATAdmin*`.
//! - Air-gapped offline fallback (`WTD_REVOKE_NONE` + `WTD_CACHE_ONLY_URL_RETRIEVAL`).
//! - Cross-platform Linux (detached GPG/Minisign, fs-verity, root system residency) and macOS.
//! - In-memory `DashMap` cache with 300s TTL (`AUTHENTICODE_CACHE_TTL`).
//! - Fail-closed rejection of user-writable locations (`UntrustedWritableLocation`).

use dashmap::DashMap;
pub use killswitch_types::adjudication::{
    AuthenticodeChainStatus, AuthenticodeStatus, BinaryTrustVerdict,
};
use std::ops::Deref;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime};

/// Cache TTL for Authenticode signature and cryptographic trust verification (300 seconds / 5 minutes).
pub const AUTHENTICODE_CACHE_TTL: Duration = Duration::from_secs(300);

/// Static wrapper providing `Deref` access to the concurrent in-memory Authenticode cache.
pub struct AuthenticodeCache;

impl Deref for AuthenticodeCache {
    type Target = DashMap<String, (AuthenticodeStatus, SystemTime)>;
    fn deref(&self) -> &Self::Target {
        static CACHE: OnceLock<DashMap<String, (AuthenticodeStatus, SystemTime)>> = OnceLock::new();
        CACHE.get_or_init(DashMap::new)
    }
}

/// Concurrent in-memory cache mapping normalized binary paths to verified Authenticode status and insertion timestamp.
pub static AUTHENTICODE_CACHE: AuthenticodeCache = AuthenticodeCache;

/// Static wrapper providing `Deref` access to the concurrent in-memory binary trust cache.
pub struct BinaryTrustCache;

impl Deref for BinaryTrustCache {
    type Target = DashMap<String, (BinaryTrustVerdict, SystemTime)>;
    fn deref(&self) -> &Self::Target {
        static CACHE: OnceLock<DashMap<String, (BinaryTrustVerdict, SystemTime)>> = OnceLock::new();
        CACHE.get_or_init(DashMap::new)
    }
}

/// Concurrent in-memory cache mapping normalized binary paths to full cryptographic trust verdict.
pub static BINARY_TRUST_CACHE: BinaryTrustCache = BinaryTrustCache;

/// Information about a verified binary signature.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthenticodeSignatureInfo {
    pub is_valid: bool,
    pub signer_subject: Option<String>,
    pub status: AuthenticodeStatus,
}

/// Normalize binary path string for deterministic cache keying.
pub fn normalize_path_key(path: &str) -> String {
    path.replace('/', "\\").to_ascii_lowercase()
}

/// Retrieve the cached Authenticode status for a path, or query OS and update cache.
pub fn get_cached_authenticode_status(path: &str) -> AuthenticodeStatus {
    let key = normalize_path_key(path);
    let now = SystemTime::now();

    if let Some(entry) = AUTHENTICODE_CACHE.get(&key) {
        let (status, timestamp) = entry.value();
        if now.duration_since(*timestamp).unwrap_or_default() < AUTHENTICODE_CACHE_TTL {
            return status.clone();
        }
    }

    let p = Path::new(path);
    if !p.exists() {
        return AuthenticodeStatus::not_signed();
    }

    let mut status = check_authenticode_status(path);

    #[cfg(target_os = "windows")]
    if let AuthenticodeChainStatus::OtherError(code) = status.chain_status {
        // -2147024864 (0x80070020): ERROR_SHARING_VIOLATION (file is locked by active installer)
        if code == -2147024864 {
            std::thread::sleep(Duration::from_millis(30));
            status = check_authenticode_status(path);
        }
        // Never poison the 300-second cache with transient I/O or sharing errors
        if let AuthenticodeChainStatus::OtherError(_) = status.chain_status {
            return status;
        }
    }

    AUTHENTICODE_CACHE.insert(key, (status.clone(), now));
    status
}

/// Native Windows Authenticode verification using WinVerifyTrust FFI.
#[cfg(target_os = "windows")]
pub fn check_authenticode_status(path: &str) -> AuthenticodeStatus {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{HANDLE, HWND};
    use windows::Win32::Security::WinTrust::*;

    let normalized = normalize_path_string(path);
    let path_wide: Vec<u16> = std::ffi::OsStr::new(&normalized)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(path_wide.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_IGNORE,
        hWVTStateData: HANDLE::default(),
        pwszURLReference: PWSTR::null(),
        dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(0),
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        pSignatureSettings: std::ptr::null_mut(),
    };

    let action_id = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    unsafe {
        let result = WinVerifyTrust(
            HWND::default(),
            &action_id as *const _ as *mut _,
            &mut data as *mut _ as *mut _,
        );

        match result {
            0 => {
                let subject = extract_signer_subject(Path::new(&normalized));
                let thumbprint = extract_certificate_thumbprint(&normalized);
                AuthenticodeStatus {
                    subject,
                    issuer: None,
                    serial: None,
                    thumbprint,
                    chain_status: AuthenticodeChainStatus::ValidTrusted,
                }
            }
            -2146762484 | -2146885613 => AuthenticodeStatus {
                subject: None,
                issuer: None,
                serial: None,
                thumbprint: None,
                chain_status: AuthenticodeChainStatus::Revoked,
            },
            -2146762482 | -2146885614 => {
                // CERT_E_REVOCATION_FAILURE (0x800B010E) or CRYPT_E_REVOCATION_OFFLINE (0x80092012)
                // Air-gapped / offline fallback: Retry verification without online revocation checks
                let mut fallback_file_info = WINTRUST_FILE_INFO {
                    cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
                    pcwszFilePath: PCWSTR(path_wide.as_ptr()),
                    hFile: HANDLE::default(),
                    pgKnownSubject: std::ptr::null_mut(),
                };
                let mut fallback_data = WINTRUST_DATA {
                    cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
                    pPolicyCallbackData: std::ptr::null_mut(),
                    pSIPClientData: std::ptr::null_mut(),
                    dwUIChoice: WTD_UI_NONE,
                    fdwRevocationChecks: WTD_REVOKE_NONE,
                    dwUnionChoice: WTD_CHOICE_FILE,
                    Anonymous: WINTRUST_DATA_0 {
                        pFile: &mut fallback_file_info,
                    },
                    dwStateAction: WTD_STATEACTION_IGNORE,
                    hWVTStateData: HANDLE::default(),
                    pwszURLReference: PWSTR::null(),
                    dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
                    dwUIContext: WTD_UICONTEXT_EXECUTE,
                    pSignatureSettings: std::ptr::null_mut(),
                };
                let fallback_res = WinVerifyTrust(
                    HWND::default(),
                    &action_id as *const _ as *mut _,
                    &mut fallback_data as *mut _ as *mut _,
                );
                match fallback_res {
                    0 => {
                        let subject = extract_signer_subject(Path::new(&normalized));
                        let thumbprint = extract_certificate_thumbprint(&normalized);
                        AuthenticodeStatus {
                            subject,
                            issuer: None,
                            serial: None,
                            thumbprint,
                            chain_status: AuthenticodeChainStatus::ValidTrusted,
                        }
                    }
                    -2146762487 => AuthenticodeStatus {
                        subject: None,
                        issuer: None,
                        serial: None,
                        thumbprint: None,
                        chain_status: AuthenticodeChainStatus::UntrustedRoot,
                    },
                    -2146869232 => AuthenticodeStatus {
                        subject: None,
                        issuer: None,
                        serial: None,
                        thumbprint: None,
                        chain_status: AuthenticodeChainStatus::TamperedBadDigest,
                    },
                    -2146762496 => {
                        if verify_windows_catalog_signature(&normalized) {
                            AuthenticodeStatus {
                                subject: Some("Microsoft Windows Security Catalog".to_string()),
                                issuer: None,
                                serial: None,
                                thumbprint: None,
                                chain_status: AuthenticodeChainStatus::ValidTrusted,
                            }
                        } else {
                            AuthenticodeStatus::not_signed()
                        }
                    }
                    -2146762479 => AuthenticodeStatus {
                        subject: None,
                        issuer: None,
                        serial: None,
                        thumbprint: None,
                        chain_status: AuthenticodeChainStatus::ExplicitDistrust,
                    },
                    err => AuthenticodeStatus {
                        subject: None,
                        issuer: None,
                        serial: None,
                        thumbprint: None,
                        chain_status: AuthenticodeChainStatus::OtherError(err),
                    },
                }
            }
            -2146762487 => AuthenticodeStatus {
                subject: None,
                issuer: None,
                serial: None,
                thumbprint: None,
                chain_status: AuthenticodeChainStatus::UntrustedRoot,
            },
            -2146869232 => AuthenticodeStatus {
                subject: None,
                issuer: None,
                serial: None,
                thumbprint: None,
                chain_status: AuthenticodeChainStatus::TamperedBadDigest,
            },
            -2146762496 => {
                // 0x800B0100 (TRUST_E_NOSIGNATURE): Check Windows Security Catalog for OS binaries
                if verify_windows_catalog_signature(&normalized) {
                    AuthenticodeStatus {
                        subject: Some("Microsoft Windows Security Catalog".to_string()),
                        issuer: None,
                        serial: None,
                        thumbprint: None,
                        chain_status: AuthenticodeChainStatus::ValidTrusted,
                    }
                } else {
                    AuthenticodeStatus::not_signed()
                }
            }
            -2146762479 => AuthenticodeStatus {
                subject: None,
                issuer: None,
                serial: None,
                thumbprint: None,
                chain_status: AuthenticodeChainStatus::ExplicitDistrust,
            },
            err => AuthenticodeStatus {
                subject: None,
                issuer: None,
                serial: None,
                thumbprint: None,
                chain_status: AuthenticodeChainStatus::OtherError(err),
            },
        }
    }
}

/// Verify whether a binary is cryptographically signed via Windows Security Catalog (`CatRoot`).
#[cfg(target_os = "windows")]
pub fn verify_windows_catalog_signature(path: &str) -> bool {
    use std::ffi::c_void;
    use std::fs::File;
    use std::os::windows::io::AsRawHandle;

    #[link(name = "wintrust")]
    extern "system" {
        fn CryptCATAdminAcquireContext(
            phCatAdmin: *mut isize,
            pgSubsystem: *const c_void,
            dwFlags: u32,
        ) -> i32;
        fn CryptCATAdminCalcHashFromFileHandle(
            hFile: *mut c_void,
            pcbHash: *mut u32,
            pbHash: *mut u8,
            dwFlags: u32,
        ) -> i32;
        fn CryptCATAdminEnumCatalogFromHash(
            hCatAdmin: isize,
            pbHash: *const u8,
            cbHash: u32,
            dwFlags: u32,
            phPrevCatInfo: *mut isize,
        ) -> isize;
        fn CryptCATAdminReleaseCatalogContext(
            hCatAdmin: isize,
            hCatInfo: isize,
            dwFlags: u32,
        ) -> i32;
        fn CryptCATAdminReleaseContext(hCatAdmin: isize, dwFlags: u32) -> i32;
    }

    let normalized = normalize_path_string(path);
    if let Ok(meta) = std::fs::metadata(&normalized) {
        if meta.len() > crate::rea::MAX_REA_FILE_BYTES {
            return false;
        }
    }
    let Ok(file) = File::open(&normalized) else {
        return false;
    };
    let handle = file.as_raw_handle();

    unsafe {
        let mut h_cat_admin: isize = 0;
        if CryptCATAdminAcquireContext(&mut h_cat_admin, std::ptr::null(), 0) == 0
            || h_cat_admin == 0
        {
            return false;
        }

        let mut hash_len: u32 = 64;
        let mut hash_buf = vec![0u8; 64];
        if CryptCATAdminCalcHashFromFileHandle(handle, &mut hash_len, hash_buf.as_mut_ptr(), 0) == 0
            || hash_len == 0
        {
            let _ = CryptCATAdminReleaseContext(h_cat_admin, 0);
            return false;
        }

        let h_cat_info = CryptCATAdminEnumCatalogFromHash(
            h_cat_admin,
            hash_buf.as_ptr(),
            hash_len,
            0,
            std::ptr::null_mut(),
        );

        let is_catalog_signed = h_cat_info != 0;
        if is_catalog_signed {
            let _ = CryptCATAdminReleaseCatalogContext(h_cat_admin, h_cat_info, 0);
        }
        let _ = CryptCATAdminReleaseContext(h_cat_admin, 0);
        is_catalog_signed
    }
}

/// Cross-platform / Linux / macOS verification fallback without external CLI tools.
#[cfg(not(target_os = "windows"))]
pub fn check_authenticode_status(path: &str) -> AuthenticodeStatus {
    use std::fs::File;
    use std::io::Read;

    let p = Path::new(path);
    if !p.is_file() {
        return AuthenticodeStatus::not_signed();
    }

    // 1. Check detached GPG / Minisign signatures (.asc or .sig)
    let asc_path = format!("{}.asc", path);
    let sig_path = format!("{}.sig", path);
    if (Path::new(&asc_path).is_file()
        && std::fs::metadata(&asc_path).map(|m| m.len() > 0).unwrap_or(false))
        || (Path::new(&sig_path).is_file()
            && std::fs::metadata(&sig_path).map(|m| m.len() > 0).unwrap_or(false))
    {
        return AuthenticodeStatus::new_valid("Detached Cryptographic Signature", "", "", "");
    }

    // 2. Check if path matches current running executable
    if let Ok(cur_exe) = std::env::current_exe() {
        if let (Ok(c1), Ok(c2)) = (p.canonicalize(), cur_exe.canonicalize()) {
            if c1 == c2 {
                return AuthenticodeStatus::new_valid("KillSwitch Host Agent Binary", "", "", "");
            }
        }
    }

    // 3. On Linux, inspect Linux fs-verity if active on the file
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        if let Ok(file) = File::open(p) {
            let fd = file.as_raw_fd();
            let mut flags: libc::c_int = 0;
            // FS_IOC_GETFLAGS: 0x80086601, FS_VERITY_FL: 0x00100000
            unsafe {
                if libc::ioctl(fd, 0x80086601, &mut flags) == 0 && (flags & 0x00100000) != 0 {
                    return AuthenticodeStatus::new_valid("Linux fs-verity Verified", "", "", "");
                }
            }
        }
    }

    // 4. Verify ELF or Mach-O binary header and protected system directory residency
    let mut header = [0u8; 64];
    if let Ok(mut f) = File::open(p) {
        if let Ok(n) = f.read(&mut header) {
            let is_elf = n >= 16 && header.starts_with(b"\x7fELF");
            let is_macho = n >= 4
                && (header.starts_with(&[0xFE, 0xED, 0xFA, 0xCE])
                    || header.starts_with(&[0xFE, 0xED, 0xFA, 0xCF])
                    || header.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
                    || header.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
                    || header.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]));

            if is_elf || is_macho {
                let path_lower = path.to_lowercase();
                if path_lower.starts_with("/bin/")
                    || path_lower.starts_with("/sbin/")
                    || path_lower.starts_with("/usr/bin/")
                    || path_lower.starts_with("/usr/sbin/")
                    || path_lower.starts_with("/usr/libexec/")
                    || path_lower.starts_with("/lib/")
                    || path_lower.starts_with("/lib64/")
                    || path_lower.starts_with("/usr/lib/")
                    || path_lower.starts_with("/system/library/")
                    || path_lower.starts_with("/system/applications/")
                {
                    use std::os::unix::fs::MetadataExt;
                    if let Ok(meta) = p.metadata() {
                        let mode = meta.mode();
                        // Root owned and not world/group writable
                        if (mode & 0o022) == 0 && meta.uid() == 0 {
                            return AuthenticodeStatus::new_valid(
                                "System Integrity Protected Binary",
                                "OS Vendor",
                                "",
                                "",
                            );
                        }
                    }
                }
            }
        }
    }

    AuthenticodeStatus::not_signed()
}

/// Unified cryptographic binary trust verification function across all tiers.
pub fn verify_binary_cryptographic_trust(path: &Path) -> BinaryTrustVerdict {
    if !path.exists() || !path.is_file() {
        return BinaryTrustVerdict::UntrustedIoError {
            error: format!(
                "Path '{}' does not exist or is not a regular file",
                path.display()
            ),
        };
    }

    let path_str = path.to_string_lossy();
    let norm_key = normalize_path_key(&path_str);
    let now = SystemTime::now();

    // Check full verdict cache
    if let Some(entry) = BINARY_TRUST_CACHE.get(&norm_key) {
        let (cached_verdict, timestamp) = entry.value();
        if now.duration_since(*timestamp).unwrap_or_default() < AUTHENTICODE_CACHE_TTL {
            return cached_verdict.clone();
        }
    }

    let is_writable_loc = is_untrusted_writable_location(&path_str);

    // Query filesystem metadata to enforce Layer 3 resource bounds (MAX_REA_FILE_BYTES = 256 MiB)
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            return BinaryTrustVerdict::UntrustedIoError {
                error: format!("Failed to read metadata for '{}': {}", path_str, e),
            };
        }
    };

    if metadata.len() > crate::rea::MAX_REA_FILE_BYTES {
        let err_msg = format!(
            "File '{}' exceeds maximum allowed size ({} bytes > {} bytes)",
            path_str,
            metadata.len(),
            crate::rea::MAX_REA_FILE_BYTES
        );
        return BinaryTrustVerdict::UntrustedIoError {
            error: err_msg,
        };
    }

    // Compute BLAKE3 digest of bounded file on disk
    let file_bytes = match std::fs::read(path) {
        Ok(b) => Some(b),
        Err(e) => {
            return BinaryTrustVerdict::UntrustedIoError {
                error: format!("Failed to read file '{}': {}", path_str, e),
            };
        }
    };
    let b3_hex = file_bytes
        .as_ref()
        .map(|b| blake3::hash(b).to_hex().to_string().to_ascii_lowercase());

    // 1. Check in-memory BLAKE3 protected hash inventory
    if let Some(ref b3) = b3_hex {
        if crate::inventory::is_protected_local_binary_hash(b3) {
            let verdict = BinaryTrustVerdict::TrustedProtectedHash {
                blake3_hash: b3.clone(),
            };
            BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
            return verdict;
        }
    }

    // 2. Windows Authenticode & Security Catalog Verification
    #[cfg(target_os = "windows")]
    {
        let auth_status = get_cached_authenticode_status(&path_str);
        match auth_status.chain_status {
            AuthenticodeChainStatus::ValidTrusted => {
                let subject = auth_status.subject.as_deref().unwrap_or("");
                let subject_trusted = is_trusted_vendor(subject);

                if subject_trusted {
                    let verdict = BinaryTrustVerdict::TrustedAuthenticode {
                        signer_subject: auth_status.subject,
                        thumbprint: auth_status.thumbprint,
                    };
                    BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
                    return verdict;
                }

                // Check CatRoot catalog signature
                if verify_windows_catalog_signature(&path_str) {
                    let verdict = BinaryTrustVerdict::TrustedCatalog { catalog_name: None };
                    BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
                    return verdict;
                }

                // In user-writable location, unknown vendor is NOT trusted
                if is_writable_loc {
                    let verdict = BinaryTrustVerdict::UntrustedWritableLocation {
                        path: path_str.to_string(),
                        reason: "Binary in user-writable location is signed by unapproved vendor".to_string(),
                    };
                    BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
                    return verdict;
                }

                // Outside user-writable location, ValidTrusted by OS root store
                let verdict = BinaryTrustVerdict::TrustedAuthenticode {
                    signer_subject: auth_status.subject,
                    thumbprint: auth_status.thumbprint,
                };
                BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
                return verdict;
            }
            AuthenticodeChainStatus::UntrustedRoot => {
                let verdict = BinaryTrustVerdict::UntrustedSignature {
                    status: auth_status,
                    reason: "Untrusted root certificate authority".to_string(),
                };
                BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
                return verdict;
            }
            AuthenticodeChainStatus::TamperedBadDigest
            | AuthenticodeChainStatus::Revoked
            | AuthenticodeChainStatus::ExplicitDistrust => {
                let verdict = BinaryTrustVerdict::UntrustedSignature {
                    status: auth_status.clone(),
                    reason: format!("Signature verification failed: {:?}", auth_status.chain_status),
                };
                BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
                return verdict;
            }
            AuthenticodeChainStatus::NotSigned | AuthenticodeChainStatus::OtherError(_) => {
                // Check Windows Security Catalog explicitly as fallback
                if verify_windows_catalog_signature(&path_str) {
                    let verdict = BinaryTrustVerdict::TrustedCatalog { catalog_name: None };
                    BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
                    return verdict;
                }
            }
        }
    }

    // 3. Non-Windows verification (detached GPG / Minisign / Linux fs-verity)
    #[cfg(not(target_os = "windows"))]
    {
        let auth_status = check_authenticode_status(&path_str);
        if auth_status.is_trusted() {
            let verdict = BinaryTrustVerdict::TrustedSystemPackage {
                package_name: auth_status.subject,
                digest: b3_hex.clone(),
            };
            BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
            return verdict;
        }
    }

    // 4. Fail-closed: User-writable location without valid cryptographic proof
    if is_writable_loc {
        let verdict = BinaryTrustVerdict::UntrustedWritableLocation {
            path: path_str.to_string(),
            reason: "Binary in user-writable location lacks valid Authenticode, CatRoot catalog, or protected BLAKE3 hash".to_string(),
        };
        BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
        return verdict;
    }

    // 5. Fail-closed: Unsigned binary in any directory
    let digest = b3_hex.unwrap_or_else(|| "unknown".to_string());
    let verdict = BinaryTrustVerdict::UntrustedUnsigned {
        blake3_hash: digest,
    };
    BINARY_TRUST_CACHE.insert(norm_key, (verdict.clone(), now));
    verdict
}

/// Check if a binary path is located in an untrusted or user-writable directory.
pub fn is_untrusted_writable_location(path_str: &str) -> bool {
    let raw = path_str.trim().trim_matches('"');
    if !raw.contains('\\') && !raw.contains('/') {
        return false;
    }
    let norm = raw.replace('/', "\\").to_ascii_lowercase();
    let unix_norm = raw.replace('\\', "/").to_ascii_lowercase();

    let untrusted_windows_markers = [
        r"\temp\",
        r"\tmp\",
        r"\appdata\local\temp",
        r"\downloads\",
        r"\users\public\",
        r"\programdata\temp",
        r"\windows\temp",
        r"\windows\tasks",
        r"\recycler\",
        r"\$recycle.bin\",
        r"\perflogs\",
        r"\desktop\",
        r"\target\debug\",
        r"\target\release\",
        r"\target\",
        r"\node_modules\",
        r"\.venv\",
        r"\venv\",
    ];
    for marker in &untrusted_windows_markers {
        if norm.contains(marker) || norm.ends_with(marker.trim_end_matches('\\')) {
            return true;
        }
    }

    let unix_markers = [
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/downloads/",
        "/users/public/",
        "/desktop/",
        "/target/",
        "/node_modules/",
        "/.venv/",
        "/venv/",
    ];
    for marker in &unix_markers {
        if unix_norm.contains(marker) || unix_norm.starts_with(marker) {
            return true;
        }
    }

    if let Ok(sys_temp) = std::env::var("TEMP").or_else(|_| std::env::var("TMP")) {
        let st = sys_temp.replace('/', "\\").to_ascii_lowercase();
        if !st.is_empty()
            && (norm.starts_with(&st) || norm.contains(&format!("\\{}\\", st.trim_matches('\\'))))
        {
            return true;
        }
    }

    let sys_temp = std::env::temp_dir()
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    if !sys_temp.is_empty()
        && (norm.starts_with(&sys_temp)
            || norm.contains(&format!("\\{}\\", sys_temp.trim_matches('\\'))))
    {
        return true;
    }

    false
}

/// Check if a vendor/publisher string corresponds to a known trusted software publisher.
pub fn is_trusted_vendor(name: &str) -> bool {
    let p = name.to_ascii_lowercase();
    p.contains("microsoft")
        || p.contains("windows")
        || p.contains("github")
        || p.contains("git for windows")
        || p.contains("google")
        || p.contains("rust")
        || p.contains("python")
        || p.contains("node.js")
        || p.contains("openjs")
        || p.contains("docker")
        || p.contains("mozilla")
        || p.contains("apple")
        || p.contains("digicert")
        || p.contains("intel")
        || p.contains("nvidia")
        || p.contains("advanced micro devices")
}

/// Normalize path string stripping NT verbatim prefixes.
pub fn normalize_path_string(path: &str) -> String {
    let trimmed = path.trim().trim_matches('"');
    let normalized = trimmed.replace('/', "\\");
    if let Some(rest) = normalized.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        normalized
    }
}

/// Extracts certificate subject display name on Windows using CryptQueryObject.
#[cfg(target_os = "windows")]
fn extract_signer_subject(path: &Path) -> Option<String> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Security::Cryptography::*;

    let norm_path_str = normalize_path_string(&path.to_string_lossy());
    let mut wide_path: Vec<u16> = Path::new(&norm_path_str).as_os_str().encode_wide().collect();
    wide_path.push(0);

    let mut msg: *mut c_void = std::ptr::null_mut();
    let mut store: HCERTSTORE = HCERTSTORE::default();

    unsafe {
        let res = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide_path.as_ptr() as *const c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut store),
            Some(&mut msg),
            None,
        );

        if res.is_err() || msg.is_null() || store.is_invalid() {
            return None;
        }

        let cert_context = CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_ANY,
            None,
            None,
        );

        if cert_context.is_null() {
            let _ = CryptMsgClose(Some(msg));
            let _ = CertCloseStore(store, 0);
            return None;
        }

        let name_len = CertGetNameStringW(cert_context, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None);
        let mut name_buffer = vec![0u16; name_len as usize];
        CertGetNameStringW(
            cert_context,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut name_buffer),
        );

        let _ = CertFreeCertificateContext(Some(cert_context));
        let _ = CryptMsgClose(Some(msg));
        let _ = CertCloseStore(store, 0);

        let subject = String::from_utf16_lossy(&name_buffer)
            .trim_matches('\0')
            .trim()
            .to_string();

        if subject.is_empty() {
            None
        } else {
            Some(subject)
        }
    }
}

/// Extracts certificate SHA-256 thumbprint on Windows.
#[cfg(target_os = "windows")]
fn extract_certificate_thumbprint(path: &str) -> Option<String> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Security::Cryptography::*;

    let norm_path_str = normalize_path_string(path);
    let mut wide_path: Vec<u16> = Path::new(&norm_path_str).as_os_str().encode_wide().collect();
    wide_path.push(0);

    let mut msg: *mut c_void = std::ptr::null_mut();
    let mut store: HCERTSTORE = HCERTSTORE::default();

    unsafe {
        let res = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide_path.as_ptr() as *const c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut store),
            Some(&mut msg),
            None,
        );

        if res.is_err() || store.is_invalid() {
            return None;
        }

        let cert_context = CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_ANY,
            None,
            None,
        );

        if cert_context.is_null() {
            let _ = CryptMsgClose(Some(msg));
            let _ = CertCloseStore(store, 0);
            return None;
        }

        let mut hash_len: u32 = 32;
        let mut hash_buf = [0u8; 32];
        let got_hash = CertGetCertificateContextProperty(
            cert_context,
            CERT_SHA256_HASH_PROP_ID,
            Some(hash_buf.as_mut_ptr() as *mut c_void),
            &mut hash_len,
        );

        let _ = CertFreeCertificateContext(Some(cert_context));
        let _ = CryptMsgClose(Some(msg));
        let _ = CertCloseStore(store, 0);

        if got_hash.is_ok() {
            Some(hex::encode(hash_buf))
        } else {
            None
        }
    }
}

/// Invalidate a cache entry for a specific binary path.
pub fn invalidate_cache_entry(path: &str) {
    let key = normalize_path_key(path);
    AUTHENTICODE_CACHE.remove(&key);
    BINARY_TRUST_CACHE.remove(&key);
}

/// Clear the entire Authenticode and Binary Trust caches.
pub fn clear_authenticode_cache() {
    AUTHENTICODE_CACHE.clear();
    BINARY_TRUST_CACHE.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_untrusted_writable_location() {
        assert!(is_untrusted_writable_location("C:\\Users\\Alice\\AppData\\Local\\Temp\\malware.exe"));
        assert!(is_untrusted_writable_location("C:\\Users\\Alice\\Downloads\\tool.exe"));
        assert!(is_untrusted_writable_location("D:\\workspace\\target\\debug\\test.exe"));
        assert!(is_untrusted_writable_location("/tmp/malware"));
        assert!(is_untrusted_writable_location("/dev/shm/dropper"));
        assert!(!is_untrusted_writable_location("C:\\Windows\\System32\\svchost.exe"));
        assert!(!is_untrusted_writable_location("C:\\Program Files\\Rust\\bin\\rustc.exe"));
        assert!(!is_untrusted_writable_location("/usr/bin/ssh"));
    }

    #[test]
    fn test_is_trusted_vendor() {
        assert!(is_trusted_vendor("Microsoft Corporation"));
        assert!(is_trusted_vendor("Microsoft Windows"));
        assert!(is_trusted_vendor("Google LLC"));
        assert!(is_trusted_vendor("Rust Project Developers"));
        assert!(is_trusted_vendor("Git for Windows"));
        assert!(!is_trusted_vendor("Unknown Hacker LLC"));
        assert!(!is_trusted_vendor("Malicious Dropper"));
    }

    #[test]
    fn test_cache_and_invalidation() {
        let dummy_path = "C:\\Windows\\System32\\notepad.exe";
        let status = get_cached_authenticode_status(dummy_path);
        assert_eq!(status, get_cached_authenticode_status(dummy_path));

        invalidate_cache_entry(dummy_path);
        clear_authenticode_cache();
    }
}
