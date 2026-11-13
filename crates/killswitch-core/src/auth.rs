//! Operator Authentication, Anti-Lockout Rate Limiting & Caller Anti-Hijacking.
//!
//! Provides pure Rust operator credential validation using constant-time comparison,
//! a 4-tier hybrid verification hierarchy, 3-strike 300-second rate-limit lockout tracking,
//! and caller process anti-hijacking validation.
//!
//! Strict Security Invariant:
//! Zero external OS CLI tools (`unix_chkpwd`, `dscl`, `powershell`, `cmd`, `sh`, `bash`).
//! Zero Win32 `LogonUserW` calls to prevent triggering host OS account lockout policies.

use chrono::Utc;
use killswitch_types::{
    constant_time_eq,
    errors::KillSwitchError,
    status::{AuthMethod, AuthResult, LockoutState, OperatorAuthenticator, OperatorCredentials},
};
use parking_lot::RwLock;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

/// Type alias for a provider closure returning currently frozen PIDs.
pub type FrozenPidsProvider = Arc<dyn Fn() -> Vec<u32> + Send + Sync>;

/// Central operator authentication controller implementing `OperatorAuthenticator`.
pub struct OperatorAuthManager {
    lockout: RwLock<LockoutState>,
    config_dir: Option<PathBuf>,
    database_dir: Option<PathBuf>,
    frozen_pids_provider: Option<FrozenPidsProvider>,
    custom_master_token: Option<String>,
}

impl Default for OperatorAuthManager {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl OperatorAuthManager {
    /// Creates a new `OperatorAuthManager` with default paths and settings.
    pub fn new(config_dir: Option<PathBuf>, database_dir: Option<PathBuf>) -> Self {
        Self {
            lockout: RwLock::new(LockoutState::default()),
            config_dir,
            database_dir,
            frozen_pids_provider: None,
            custom_master_token: None,
        }
    }

    /// Sets the dynamic provider for retrieving currently frozen PIDs.
    pub fn set_frozen_pids_provider(&mut self, provider: FrozenPidsProvider) {
        self.frozen_pids_provider = Some(provider);
    }

    /// Sets an optional custom master token.
    pub fn set_custom_master_token(&mut self, token: String) {
        self.custom_master_token = Some(token);
    }

    /// Helper to get currently frozen PIDs from provider if configured.
    fn get_current_frozen_pids(&self) -> Vec<u32> {
        if let Some(ref provider) = self.frozen_pids_provider {
            provider()
        } else {
            Vec::new()
        }
    }

    /// Resolves configuration search roots for admin hash files.
    fn get_hash_file_paths(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // 1. Explicit config dir
        if let Some(ref dir) = self.config_dir {
            paths.push(dir.join("admin_password.hash"));
            paths.push(dir.join("admin_auth.json"));
        }

        // 2. Explicit or env database dir
        if let Some(ref dir) = self.database_dir {
            paths.push(dir.join("admin_password.hash"));
            paths.push(dir.join("admin_auth.json"));
        } else if let Ok(env_dir) = std::env::var("KILLSWITCH_DATABASE_DIR")
            .or_else(|_| std::env::var("OSOOSI_DATABASE_DIR"))
        {
            let p = PathBuf::from(env_dir.trim());
            paths.push(p.join("admin_password.hash"));
            paths.push(p.join("admin_auth.json"));
        }

        // 3. Fallback relative defaults
        paths.push(PathBuf::from("config").join("admin_password.hash"));
        paths.push(PathBuf::from("config").join("admin_auth.json"));
        paths.push(PathBuf::from("database").join("admin_password.hash"));
        paths.push(PathBuf::from("database").join("admin_auth.json"));

        paths
    }

    /// Internal evaluation of Tier 1: Master Token Bypass.
    /// Requires a high-entropy CSPRNG-generated master token or explicit secret (>= 32 chars).
    fn verify_tier1_master_token(&self, candidate: &str) -> bool {
        let trimmed = candidate.trim();
        if trimmed.len() < 32 || is_forbidden_static_token(trimmed) {
            // Reject low-entropy, empty, or static legacy/confirmation phrases
            return false;
        }

        // Custom configured master token (CSPRNG provisioned at startup, >= 32 chars)
        if let Some(ref master) = self.custom_master_token {
            let m_trimmed = master.trim();
            if m_trimmed.len() >= 32
                && !is_forbidden_static_token(m_trimmed)
                && constant_time_eq(trimmed, m_trimmed)
            {
                return true;
            }
        }

        // Environment master token (>= 32 chars)
        if let Ok(env_master) = std::env::var("KILLSWITCH_MASTER_TOKEN")
            .or_else(|_| std::env::var("KILLSWITCH_CONTROL_TOKEN"))
        {
            let env_trimmed = env_master.trim();
            if env_trimmed.len() >= 32
                && !is_forbidden_static_token(env_trimmed)
                && constant_time_eq(trimmed, env_trimmed)
            {
                return true;
            }
        }

        // Host DPAPI/ACL-protected CSPRNG control secret (when custom override is not pinned)
        if self.custom_master_token.is_none() {
            if let Ok(Some(host_secret)) = try_load_host_control_secret() {
                let host_trimmed = host_secret.trim();
                if host_trimmed.len() >= 32
                    && !is_forbidden_static_token(host_trimmed)
                    && constant_time_eq(trimmed, host_trimmed)
                {
                    return true;
                }
            }
        }

        false
    }

    /// Internal evaluation of Tier 2: Environment Admin Password.
    fn verify_tier2_environment_password(&self, candidate: &str) -> bool {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            return false;
        }

        for var_name in &["KILLSWITCH_ADMIN_PASSWORD", "OSOOSI_ADMIN_PASSWORD"] {
            if let Ok(env_val) = std::env::var(var_name) {
                let clean = env_val.trim();
                if !clean.is_empty() && constant_time_eq(trimmed, clean) {
                    return true;
                }
            }
        }

        false
    }

    /// Internal evaluation of Tier 3: Stored Admin Password Hash.
    fn verify_tier3_stored_hash(&self, candidate: &str) -> bool {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            return false;
        }

        let computed_b3 = blake3::hash(trimmed.as_bytes()).to_hex().to_string();
        let mut sha256_hasher = sha2::Sha256::default();
        sha2::Digest::update(&mut sha256_hasher, trimmed.as_bytes());
        let computed_sha = hex::encode(sha2::Digest::finalize(sha256_hasher));

        for path in self.get_hash_file_paths() {
            if !path.is_file() {
                continue;
            }

            if let Ok(content) = std::fs::read_to_string(&path) {
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    // JSON format: {"password_hash": "...", "hash": "..."}
                    if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&content) {
                        for key in &["password_hash", "hash", "token", "pin_hash"] {
                            if let Some(stored) = json_val.get(*key).and_then(|v| v.as_str()) {
                                let clean = stored.trim();
                                if verify_stored_hash_digest(trimmed, &computed_b3, &computed_sha, clean)
                                {
                                    return true;
                                }
                            }
                        }
                    }
                } else {
                    // Plain text hash file
                    let clean = content.trim();
                    if verify_stored_hash_digest(trimmed, &computed_b3, &computed_sha, clean)
                    {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Internal evaluation of Tier 4: Linux `/etc/shadow` FFI `crypt(3)`.
    #[cfg(target_os = "linux")]
    fn verify_tier4_linux_shadow(&self, username: &str, password: &str) -> bool {
        let user = username.trim();
        let pass = password.trim();
        if user.is_empty() || pass.is_empty() {
            return false;
        }

        let shadow_path = Path::new("/etc/shadow");
        if !shadow_path.exists() {
            return false;
        }

        let Ok(shadow_data) = std::fs::read_to_string(shadow_path) else {
            return false;
        };

        for line in shadow_data.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 2 && parts[0] == user {
                let stored_hash = parts[1].trim();
                // Reject disabled/locked accounts
                if stored_hash == "*"
                    || stored_hash == "!"
                    || stored_hash.starts_with('!')
                    || stored_hash.is_empty()
                {
                    return false;
                }

                // Call native crypt(3) FFI
                let pass_c = match std::ffi::CString::new(pass) {
                    Ok(c) => c,
                    Err(_) => return false,
                };
                let salt_c = match std::ffi::CString::new(stored_hash) {
                    Ok(c) => c,
                    Err(_) => return false,
                };

                static CRYPT_MUTEX: parking_lot::Mutex<()> = parking_lot::Mutex::new(());
                let _guard = CRYPT_MUTEX.lock();

                unsafe {
                    #[link(name = "crypt")]
                    extern "C" {
                        fn crypt(
                            key: *const libc::c_char,
                            salt: *const libc::c_char,
                        ) -> *mut libc::c_char;
                    }
                    let res_ptr = crypt(pass_c.as_ptr(), salt_c.as_ptr());
                    if !res_ptr.is_null() {
                        let computed_cstr = std::ffi::CStr::from_ptr(res_ptr);
                        if let Ok(computed_str) = computed_cstr.to_str() {
                            if constant_time_eq(computed_str, stored_hash) {
                                return true;
                            }
                        }
                    }
                }
                break;
            }
        }

        false
    }

    #[cfg(not(target_os = "linux"))]
    fn verify_tier4_linux_shadow(&self, _username: &str, _password: &str) -> bool {
        // Non-Linux platforms: zero-touch, no LogonUserW, no dscl
        false
    }
}

impl OperatorAuthenticator for OperatorAuthManager {
    fn authenticate(&self, creds: &OperatorCredentials) -> AuthResult {
        // Stage 0: Anti-Hijacking Caller PID Validation
        if let Err(err) = self.validate_caller(creds.caller_pid) {
            match err {
                KillSwitchError::InvalidCallerPid { pid } => {
                    return AuthResult::CallerQuarantined {
                        caller_pid: pid,
                        reason: "Calling PID <= 4 (Kernel/System/Idle) is invalid".to_string(),
                    };
                }
                KillSwitchError::CallerQuarantined { pid } => {
                    return AuthResult::CallerQuarantined {
                        caller_pid: pid,
                        reason: "Calling process is actively frozen under containment".to_string(),
                    };
                }
                _ => {}
            }
        }

        // Candidates for authentication
        let candidate_token = creds.auth_token.as_deref().unwrap_or_default().trim();
        let candidate_pass = creds.password.as_deref().unwrap_or_default().trim();
        let candidate_phrase = creds
            .confirmation_phrase
            .as_deref()
            .unwrap_or_default()
            .trim();

        // ---------------------------------------------------------------------
        // Tier 1: Master Token Bypass (ALWAYS runs first, bypassing lockout)
        // ---------------------------------------------------------------------
        for cand in &[candidate_token, candidate_pass, candidate_phrase] {
            if !cand.is_empty() && self.verify_tier1_master_token(cand) {
                let mut lock = self.lockout.write();
                lock.record_success();
                info!(
                    "🟢 [AUTH] Operator '{}' authenticated via Tier 1: Master Token Bypass",
                    creds.operator_id
                );
                return AuthResult::Success {
                    operator: creds.operator_id.clone(),
                    method: AuthMethod::MasterTokenBypass,
                    authenticated_at: Utc::now(),
                };
            }
        }

        // ---------------------------------------------------------------------
        // Lockout Check for Tiers 2-4
        // ---------------------------------------------------------------------
        {
            let mut lock = self.lockout.write();
            if lock.is_currently_locked() {
                let locked_until = lock.locked_at.unwrap_or_else(Utc::now)
                    + chrono::Duration::seconds(lock.lockout_duration_secs as i64);
                warn!(
                    "🚨 [AUTH] Authentication rejected: Interface locked out for {} more seconds",
                    lock.lockout_remaining_secs
                );
                return AuthResult::LockedOut {
                    remaining_seconds: lock.lockout_remaining_secs,
                    locked_until,
                };
            }
        }

        // ---------------------------------------------------------------------
        // Tier 2: Environment Admin Password
        // ---------------------------------------------------------------------
        for cand in &[candidate_token, candidate_pass] {
            if !cand.is_empty() && self.verify_tier2_environment_password(cand) {
                let mut lock = self.lockout.write();
                lock.record_success();
                info!(
                    "🟢 [AUTH] Operator '{}' authenticated via Tier 2: Environment Password",
                    creds.operator_id
                );
                return AuthResult::Success {
                    operator: creds.operator_id.clone(),
                    method: AuthMethod::EnvironmentPassword,
                    authenticated_at: Utc::now(),
                };
            }
        }

        // ---------------------------------------------------------------------
        // Tier 3: Stored Admin Password Hash Match (BLAKE3 / SHA-256)
        // ---------------------------------------------------------------------
        for cand in &[candidate_token, candidate_pass] {
            if !cand.is_empty() && self.verify_tier3_stored_hash(cand) {
                let mut lock = self.lockout.write();
                lock.record_success();
                info!(
                    "🟢 [AUTH] Operator '{}' authenticated via Tier 3: Stored Hash Match",
                    creds.operator_id
                );
                return AuthResult::Success {
                    operator: creds.operator_id.clone(),
                    method: AuthMethod::StoredHashMatch,
                    authenticated_at: Utc::now(),
                };
            }
        }

        // ---------------------------------------------------------------------
        // Tier 4: Linux `/etc/shadow` FFI `crypt(3)`
        // ---------------------------------------------------------------------
        if !candidate_pass.is_empty()
            && self.verify_tier4_linux_shadow(&creds.operator_id, candidate_pass)
        {
            let mut lock = self.lockout.write();
            lock.record_success();
            info!(
                "🟢 [AUTH] Operator '{}' authenticated via Tier 4: Linux Shadow FFI",
                creds.operator_id
            );
            return AuthResult::Success {
                operator: creds.operator_id.clone(),
                method: AuthMethod::LinuxShadowCryptFfi,
                authenticated_at: Utc::now(),
            };
        }

        // ---------------------------------------------------------------------
        // All checks failed: Record strike and enforce lockout if threshold hit
        // ---------------------------------------------------------------------
        let mut lock = self.lockout.write();
        let result = lock.record_failure(creds.caller_pid);
        warn!(
            "❌ [AUTH] Authentication failure for operator '{}' (PID: {:?}). Strike {}/{}",
            creds.operator_id, creds.caller_pid, lock.failed_attempts, lock.max_failed_attempts
        );
        result
    }

    fn validate_caller(&self, caller_pid: Option<u32>) -> Result<(), KillSwitchError> {
        let frozen = self.get_current_frozen_pids();
        killswitch_types::validate_caller_pid(caller_pid, &frozen)
    }

    fn check_lockout(&self) -> LockoutState {
        let mut lock = self.lockout.write();
        let _ = lock.is_currently_locked();
        lock.clone()
    }

    fn reset_lockout(&self) {
        let mut lock = self.lockout.write();
        lock.reset();
        info!("🔓 [AUTH] Security rate-limit lockout manually reset.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use killswitch_types::status::KILLCHAIN_RESTORE_CONFIRMATION_PHRASE;

    #[test]
    fn test_tier1_master_token_bypass_and_lockout_reset() {
        let mut auth = OperatorAuthManager::new(None, None);

        // Intentionally rack up 3 failures to trigger lockout
        for _ in 0..3 {
            let creds = OperatorCredentials {
                operator_id: "attacker".to_string(),
                auth_token: None,
                password: Some("wrong_password".to_string()),
                caller_pid: Some(5000),
                confirmation_phrase: None,
            };
            let _ = auth.authenticate(&creds);
        }

        assert!(auth.check_lockout().is_locked);

        // Static "CONFIRM RESTORE" must be REJECTED and lockout preserved
        let static_bypass_creds = OperatorCredentials {
            operator_id: "admin".to_string(),
            auth_token: None,
            password: None,
            caller_pid: Some(5000),
            confirmation_phrase: Some(KILLCHAIN_RESTORE_CONFIRMATION_PHRASE.to_string()),
        };
        let static_res = auth.authenticate(&static_bypass_creds);
        assert!(!static_res.is_success());
        assert!(auth.check_lockout().is_locked);

        // Operator configures valid CSPRNG >= 32-char master token
        let secure_token = "a_cryptographically_secure_token_32_chars_long_1234567";
        auth.set_custom_master_token(secure_token.to_string());

        let master_creds = OperatorCredentials {
            operator_id: "admin".to_string(),
            auth_token: Some(secure_token.to_string()),
            password: None,
            caller_pid: Some(5000),
            confirmation_phrase: None,
        };

        let result = auth.authenticate(&master_creds);
        assert!(result.is_success());
        if let AuthResult::Success { method, .. } = result {
            assert_eq!(method, AuthMethod::MasterTokenBypass);
        }

        // Lockout must be immediately reset
        assert!(!auth.check_lockout().is_locked);
    }

    #[test]
    fn test_caller_pid_anti_hijacking_rejection() {
        let mut auth = OperatorAuthManager::new(None, None);
        auth.set_frozen_pids_provider(std::sync::Arc::new(|| vec![9999, 8888]));

        // PID 4 (System) must be rejected
        let r_system = auth.validate_caller(Some(4));
        assert!(r_system.is_err());

        // Frozen PID 9999 must be rejected
        let r_frozen = auth.validate_caller(Some(9999));
        assert!(r_frozen.is_err());

        // Normal PID 1234 allowed
        assert!(auth.validate_caller(Some(1234)).is_ok());
    }

    #[test]
    fn test_tier3_stored_blake3_and_sha256_hash_verification() {
        let dir = tempfile::tempdir().unwrap();
        let hash_file = dir.path().join("admin_password.hash");
        let secret = "SuperSecretAdminPhrase2026!";
        let hash_b3 = blake3::hash(secret.as_bytes()).to_hex().to_string();
        std::fs::write(&hash_file, hash_b3).unwrap();

        let auth = OperatorAuthManager::new(Some(dir.path().to_path_buf()), None);

        let creds = OperatorCredentials {
            operator_id: "sec_admin".to_string(),
            auth_token: None,
            password: Some(secret.to_string()),
            caller_pid: Some(4000),
            confirmation_phrase: None,
        };

        let res = auth.authenticate(&creds);
        assert!(res.is_success());
        if let AuthResult::Success { method, .. } = res {
            assert_eq!(method, AuthMethod::StoredHashMatch);
        }
    }

    #[test]
    fn test_hardcoded_legacy_master_token_rejected() {
        let auth = OperatorAuthManager::new(None, None);
        let legacy = "KS-TOKEN-SEC-REM-9999-VERIFIED-AUTH";
        let creds = OperatorCredentials {
            operator_id: "adversary".to_string(),
            auth_token: Some(legacy.to_string()),
            password: None,
            caller_pid: Some(5000),
            confirmation_phrase: None,
        };
        assert!(!auth.authenticate(&creds).is_success());
    }

    #[test]
    fn test_tier3_plaintext_stored_password_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let hash_file = dir.path().join("admin_password.hash");
        let plaintext = "PlaintextSecretNotAHash1234567890!";
        std::fs::write(&hash_file, plaintext).unwrap();

        let auth = OperatorAuthManager::new(Some(dir.path().to_path_buf()), None);
        let creds = OperatorCredentials {
            operator_id: "sec_admin".to_string(),
            auth_token: None,
            password: Some(plaintext.to_string()),
            caller_pid: Some(4000),
            confirmation_phrase: None,
        };
        assert!(!auth.authenticate(&creds).is_success());
    }

    #[test]
    fn test_tier3_pbkdf2_sha256_verification() {
        let dir = tempfile::tempdir().unwrap();
        let hash_file = dir.path().join("admin_password.hash");
        let secret = "StrongOperatorSecret!2026";
        let phc = encode_pbkdf2_sha256_phc(secret, 10_000).unwrap();
        std::fs::write(&hash_file, &phc).unwrap();

        let auth = OperatorAuthManager::new(Some(dir.path().to_path_buf()), None);
        let creds = OperatorCredentials {
            operator_id: "sec_admin".to_string(),
            auth_token: None,
            password: Some(secret.to_string()),
            caller_pid: Some(4000),
            confirmation_phrase: None,
        };
        assert!(auth.authenticate(&creds).is_success());

        let bad_creds = OperatorCredentials {
            password: Some("WrongSecret!".to_string()),
            ..creds
        };
        assert!(!auth.authenticate(&bad_creds).is_success());
    }

    #[test]
    fn test_csprng_operator_secret_provisioning_and_unseal() {
        let dir = tempfile::tempdir().unwrap();
        let secret1 = load_or_provision_operator_secret_in(dir.path()).unwrap();
        assert!(secret1.len() >= 64);
        assert!(!is_forbidden_static_token(&secret1));

        let secret2 = load_or_provision_operator_secret_in(dir.path()).unwrap();
        assert_eq!(secret1, secret2);

        let random_a = generate_csprng_token_hex().unwrap();
        let random_b = generate_csprng_token_hex().unwrap();
        assert_ne!(random_a, random_b);
    }
}

/// Returns `true` if `candidate` matches a known forbidden legacy static token or confirmation phrase.
pub fn is_forbidden_static_token(candidate: &str) -> bool {
    let trimmed = candidate.trim();
    trimmed.eq_ignore_ascii_case("KS-TOKEN-SEC-REM-9999-VERIFIED-AUTH")
        || trimmed.eq_ignore_ascii_case("CONFIRM RESTORE")
        || trimmed.eq_ignore_ascii_case("CONFIRM ISOLATE")
}

/// Generates a 256-bit cryptographically random operator token encoded cleanly (`ks-op-<64 hex>`).
pub fn generate_csprng_token_hex() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    fill_os_csprng(&mut bytes)?;
    Ok(format!("ks-op-{}", hex::encode(bytes)))
}

#[cfg(target_os = "windows")]
fn fill_os_csprng(buf: &mut [u8]) -> Result<(), String> {
    use std::ffi::c_void;
    type FnBCryptGenRandom =
        unsafe extern "system" fn(*mut c_void, *mut u8, u32, u32) -> i32;
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryA(lp_lib_file_name: *const u8) -> *mut c_void;
        fn GetProcAddress(h_module: *mut c_void, lp_proc_name: *const u8) -> *mut c_void;
    }
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    unsafe {
        let h_bcrypt = LoadLibraryA(c"bcrypt.dll".as_ptr().cast());
        if h_bcrypt.is_null() {
            return Err("Failed to load bcrypt.dll for OS CSPRNG".to_string());
        }
        let proc = GetProcAddress(h_bcrypt, c"BCryptGenRandom".as_ptr().cast());
        if proc.is_null() {
            return Err("Failed to resolve BCryptGenRandom".to_string());
        }
        let gen_random: FnBCryptGenRandom = std::mem::transmute(proc);
        let status = gen_random(
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        );
        if status != 0 {
            return Err(format!("BCryptGenRandom failed with NTSTATUS 0x{:08x}", status));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn fill_os_csprng(buf: &mut [u8]) -> Result<(), String> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| format!("Failed to open /dev/urandom for CSPRNG: {}", e))?;
    f.read_exact(buf)
        .map_err(|e| format!("Failed to read CSPRNG bytes from /dev/urandom: {}", e))?;
    Ok(())
}

/// Strictly verifies a password candidate against stored cryptographic hashes or KDF strings.
/// Zero plaintext equality fallback is permitted.
pub fn verify_stored_hash_digest(
    candidate: &str,
    computed_b3: &str,
    computed_sha: &str,
    stored: &str,
) -> bool {
    let clean = stored.trim();
    if clean.is_empty() {
        return false;
    }
    if clean.starts_with("$pbkdf2-sha256$") {
        return verify_pbkdf2_sha256_phc(candidate, clean);
    }
    if clean.len() == 64 && clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        let normalized = clean.to_ascii_lowercase();
        return constant_time_eq(computed_b3, &normalized)
            || constant_time_eq(computed_sha, &normalized);
    }
    false
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let digest = Sha256::digest(key);
        k_block[..32].copy_from_slice(&digest);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let out = outer.finalize();
    let mut res = [0u8; 32];
    res.copy_from_slice(&out);
    res
}

fn pbkdf2_hmac_sha256_32(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut msg = Vec::with_capacity(salt.len() + 4);
    msg.extend_from_slice(salt);
    msg.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac_sha256(password, &msg);
    let mut acc = u;
    for _ in 1..iterations {
        u = hmac_sha256(password, &u);
        for (a, b) in acc.iter_mut().zip(u.iter()) {
            *a ^= *b;
        }
    }
    acc
}

/// Encodes a password using PBKDF2-HMAC-SHA256 in PHC format (`$pbkdf2-sha256$iters$salt_hex$dk_hex`).
pub fn encode_pbkdf2_sha256_phc(password: &str, iterations: u32) -> Result<String, String> {
    let iters = iterations.max(10_000);
    let mut salt = [0u8; 16];
    fill_os_csprng(&mut salt)?;
    let dk = pbkdf2_hmac_sha256_32(password.as_bytes(), &salt, iters);
    Ok(format!(
        "$pbkdf2-sha256${}${}${}",
        iters,
        hex::encode(salt),
        hex::encode(dk)
    ))
}

fn verify_pbkdf2_sha256_phc(candidate: &str, phc: &str) -> bool {
    let parts: Vec<&str> = phc.split('$').collect();
    if parts.len() != 5 || parts[1] != "pbkdf2-sha256" {
        return false;
    }
    let Ok(iters) = parts[2].parse::<u32>() else {
        return false;
    };
    if iters < 10_000 {
        return false;
    }
    let Ok(salt) = hex::decode(parts[3]) else {
        return false;
    };
    if salt.len() < 8 || parts[4].len() != 64 {
        return false;
    }
    let dk = pbkdf2_hmac_sha256_32(candidate.as_bytes(), &salt, iters);
    let computed_hex = hex::encode(dk);
    constant_time_eq(&computed_hex, &parts[4].to_ascii_lowercase())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SealedControlSecretEnvelope {
    schema_version: u32,
    platform: String,
    sealed_hex: String,
    envelope_mac_blake3: String,
}

const CONTROL_SECRET_FILE: &str = "control.secret.seal";
const CONTROL_SECRET_ENTROPY: &[u8] = b"KILLSWITCH_CONTROL_PLANE_SECRET_V1";

/// Resolves the privileged runtime secret directory.
pub fn default_control_secret_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("KILLSWITCH_RUNTIME_DIR")
        .or_else(|_| std::env::var("KILLSWITCH_DATABASE_DIR"))
    {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return std::path::PathBuf::from(trimmed);
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Ok(pd) = std::env::var("ProgramData") {
            let trimmed = pd.trim();
            if !trimmed.is_empty() {
                return std::path::PathBuf::from(trimmed)
                    .join("KillSwitch")
                    .join("runtime");
            }
        }
        std::path::PathBuf::from(r"C:\ProgramData\KillSwitch\runtime")
    }
    #[cfg(target_os = "macos")]
    {
        std::path::PathBuf::from("/Library/Application Support/KillSwitch/runtime")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::path::PathBuf::from("/var/lib/killswitch/runtime")
    }
}

fn secret_envelope_mac(sealed_hex: &str) -> String {
    let key = blake3::hash(CONTROL_SECRET_ENTROPY);
    let mut h = blake3::Hasher::new_keyed(key.as_bytes());
    h.update(b"v1:");
    h.update(sealed_hex.as_bytes());
    h.finalize().to_hex().to_string()
}

/// Attempts to load and unseal an existing host-protected operator control secret.
/// Returns `Ok(None)` if not yet provisioned, or `Err` fail-closed on ACL/corruption/MAC failure.
pub fn try_load_host_control_secret_in(dir: &std::path::Path) -> Result<Option<String>, String> {
    let path = dir.join(CONTROL_SECRET_FILE);
    if !path.exists() {
        return Ok(None);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(&path)
            .map_err(|e| format!("Failed to stat {}: {}", path.display(), e))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "Refusing control secret at {} with insecure permissions {:o} (group/other accessible)",
                path.display(),
                mode
            ));
        }
    }

    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read control secret {}: {}", path.display(), e))?;
    let env: SealedControlSecretEnvelope = serde_json::from_str(&raw)
        .map_err(|e| format!("Corrupt control secret envelope {}: {}", path.display(), e))?;
    let expected_mac = secret_envelope_mac(&env.sealed_hex);
    if !constant_time_eq(&env.envelope_mac_blake3, &expected_mac) {
        return Err(format!(
            "Control secret envelope MAC mismatch at {}",
            path.display()
        ));
    }

    let sealed_bytes = hex::decode(&env.sealed_hex)
        .map_err(|e| format!("Invalid hex in control secret envelope: {}", e))?;
    let plaintext = unseal_platform_secret_bytes(&sealed_bytes)?;
    let secret = String::from_utf8(plaintext)
        .map_err(|e| format!("Non-UTF8 control secret payload: {}", e))?;
    let trimmed = secret.trim().to_string();
    if trimmed.len() < 32 || is_forbidden_static_token(&trimmed) {
        return Err("Unsealed control secret failed strength validation".to_string());
    }
    Ok(Some(trimmed))
}

/// Attempts to load an existing host-protected operator control secret from the default directory.
pub fn try_load_host_control_secret() -> Result<Option<String>, String> {
    try_load_host_control_secret_in(&default_control_secret_dir())
}

/// Seals and atomically stores a CSPRNG operator control secret in `dir` with strict ACLs (`SYSTEM`+`Admin` or `0600`).
pub fn seal_and_store_operator_secret(
    dir: &std::path::Path,
    secret: &str,
) -> Result<std::path::PathBuf, String> {
    let trimmed = secret.trim();
    if trimmed.len() < 32 || is_forbidden_static_token(trimmed) {
        return Err("Refusing to store weak or static control secret".to_string());
    }
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("Failed to create runtime secret dir {}: {}", dir.display(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }

    let sealed_bytes = seal_platform_secret_bytes(trimmed.as_bytes())?;
    let sealed_hex = hex::encode(sealed_bytes);
    let envelope = SealedControlSecretEnvelope {
        schema_version: 1,
        platform: std::env::consts::OS.to_string(),
        envelope_mac_blake3: secret_envelope_mac(&sealed_hex),
        sealed_hex,
    };
    let json = serde_json::to_string_pretty(&envelope)
        .map_err(|e| format!("Serialize control secret envelope failed: {}", e))?;

    let final_path = dir.join(CONTROL_SECRET_FILE);
    let tmp_path = dir.join(format!("{}.tmp.{}", CONTROL_SECRET_FILE, std::process::id()));

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| format!("Open temp secret file failed: {}", e))?;
        f.write_all(json.as_bytes())
            .map_err(|e| format!("Write temp secret file failed: {}", e))?;
        f.sync_all()
            .map_err(|e| format!("Sync temp secret file failed: {}", e))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&tmp_path, json.as_bytes())
            .map_err(|e| format!("Write temp secret file failed: {}", e))?;
    }

    #[cfg(target_os = "windows")]
    harden_windows_secret_dacl(&tmp_path)?;

    std::fs::rename(&tmp_path, &final_path)
        .map_err(|e| format!("Atomic rename secret file failed: {}", e))?;

    #[cfg(target_os = "windows")]
    harden_windows_secret_dacl(&final_path)?;

    Ok(final_path)
}

/// Loads an existing sealed CSPRNG operator secret or provisions a fresh 256-bit secret in `dir`.
pub fn load_or_provision_operator_secret_in(dir: &std::path::Path) -> Result<String, String> {
    if let Some(existing) = try_load_host_control_secret_in(dir)? {
        return Ok(existing);
    }
    let fresh = generate_csprng_token_hex()?;
    seal_and_store_operator_secret(dir, &fresh)?;
    Ok(fresh)
}

/// Loads or provisions the host-protected CSPRNG operator secret in the default runtime directory.
pub fn load_or_provision_host_control_secret() -> Result<String, String> {
    load_or_provision_operator_secret_in(&default_control_secret_dir())
}

#[cfg(target_os = "windows")]
fn seal_platform_secret_bytes(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    use std::ffi::c_void;
    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }
    type FnCryptProtectData = unsafe extern "system" fn(
        *const DataBlob,
        *const u16,
        *const DataBlob,
        *mut c_void,
        *mut c_void,
        u32,
        *mut DataBlob,
    ) -> i32;
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryA(lp_lib_file_name: *const u8) -> *mut c_void;
        fn GetProcAddress(h_module: *mut c_void, lp_proc_name: *const u8) -> *mut c_void;
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
    }
    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x01;
    const CRYPTPROTECT_LOCAL_MACHINE: u32 = 0x04;
    unsafe {
        let h_crypt = LoadLibraryA(c"crypt32.dll".as_ptr().cast());
        if h_crypt.is_null() {
            return Err("Failed to load crypt32.dll for DPAPI seal".to_string());
        }
        let proc = GetProcAddress(h_crypt, c"CryptProtectData".as_ptr().cast());
        if proc.is_null() {
            return Err("Failed to resolve CryptProtectData".to_string());
        }
        let crypt_protect: FnCryptProtectData = std::mem::transmute(proc);
        let mut in_buf = plaintext.to_vec();
        let mut ent_buf = CONTROL_SECRET_ENTROPY.to_vec();
        let in_blob = DataBlob {
            cb_data: in_buf.len() as u32,
            pb_data: in_buf.as_mut_ptr(),
        };
        let ent_blob = DataBlob {
            cb_data: ent_buf.len() as u32,
            pb_data: ent_buf.as_mut_ptr(),
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: std::ptr::null_mut(),
        };
        let ok = crypt_protect(
            &in_blob,
            std::ptr::null(),
            &ent_blob,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
            &mut out_blob,
        );
        if ok == 0 || out_blob.pb_data.is_null() || out_blob.cb_data == 0 {
            return Err("DPAPI CryptProtectData failed for control secret".to_string());
        }
        let sealed =
            std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize).to_vec();
        let _ = LocalFree(out_blob.pb_data as *mut c_void);
        Ok(sealed)
    }
}

#[cfg(target_os = "windows")]
fn unseal_platform_secret_bytes(ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    use std::ffi::c_void;
    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }
    type FnCryptUnprotectData = unsafe extern "system" fn(
        *const DataBlob,
        *mut *mut u16,
        *const DataBlob,
        *mut c_void,
        *mut c_void,
        u32,
        *mut DataBlob,
    ) -> i32;
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryA(lp_lib_file_name: *const u8) -> *mut c_void;
        fn GetProcAddress(h_module: *mut c_void, lp_proc_name: *const u8) -> *mut c_void;
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
    }
    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x01;
    unsafe {
        let h_crypt = LoadLibraryA(c"crypt32.dll".as_ptr().cast());
        if h_crypt.is_null() {
            return Err("Failed to load crypt32.dll for DPAPI unseal".to_string());
        }
        let proc = GetProcAddress(h_crypt, c"CryptUnprotectData".as_ptr().cast());
        if proc.is_null() {
            return Err("Failed to resolve CryptUnprotectData".to_string());
        }
        let crypt_unprotect: FnCryptUnprotectData = std::mem::transmute(proc);
        let mut in_buf = ciphertext.to_vec();
        let mut ent_buf = CONTROL_SECRET_ENTROPY.to_vec();
        let in_blob = DataBlob {
            cb_data: in_buf.len() as u32,
            pb_data: in_buf.as_mut_ptr(),
        };
        let ent_blob = DataBlob {
            cb_data: ent_buf.len() as u32,
            pb_data: ent_buf.as_mut_ptr(),
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: std::ptr::null_mut(),
        };
        let ok = crypt_unprotect(
            &in_blob,
            std::ptr::null_mut(),
            &ent_blob,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out_blob,
        );
        if ok == 0 || out_blob.pb_data.is_null() || out_blob.cb_data == 0 {
            return Err("DPAPI CryptUnprotectData failed for control secret".to_string());
        }
        let unsealed =
            std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize).to_vec();
        let _ = LocalFree(out_blob.pb_data as *mut c_void);
        Ok(unsealed)
    }
}

#[cfg(target_os = "windows")]
fn harden_windows_secret_dacl(path: &std::path::Path) -> Result<(), String> {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;

    #[repr(C)]
    struct TokenElevation {
        token_is_elevated: u32,
    }
    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut c_void,
        attributes: u32,
    }

    type FnConvertSddl = unsafe extern "system" fn(*const u16, u32, *mut *mut c_void, *mut u32) -> i32;
    type FnGetDacl = unsafe extern "system" fn(*mut c_void, *mut i32, *mut *mut c_void, *mut i32) -> i32;
    type FnSetNamedSec = unsafe extern "system" fn(
        *const u16,
        u32,
        u32,
        *mut c_void,
        *mut c_void,
        *mut c_void,
        *mut c_void,
    ) -> u32;
    type FnOpenProcessToken = unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32;
    type FnGetTokenInfo =
        unsafe extern "system" fn(*mut c_void, u32, *mut c_void, u32, *mut u32) -> i32;
    type FnConvertSidToStringSidW = unsafe extern "system" fn(*mut c_void, *mut *mut u16) -> i32;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryA(lp_lib_file_name: *const u8) -> *mut c_void;
        fn GetProcAddress(h_module: *mut c_void, lp_proc_name: *const u8) -> *mut c_void;
        fn GetCurrentProcess() -> *mut c_void;
        fn CloseHandle(h: *mut c_void) -> i32;
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
    }

    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_USER: u32 = 1;
    const TOKEN_ELEVATION: u32 = 20;
    const SE_FILE_OBJECT: u32 = 1;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

    unsafe {
        let h_adv = LoadLibraryA(c"advapi32.dll".as_ptr().cast());
        if h_adv.is_null() {
            return Err("Failed to load advapi32.dll for DACL hardening".to_string());
        }
        let p_sddl = GetProcAddress(
            h_adv,
            c"ConvertStringSecurityDescriptorToSecurityDescriptorW".as_ptr().cast(),
        );
        let p_dacl = GetProcAddress(h_adv, c"GetSecurityDescriptorDacl".as_ptr().cast());
        let p_set = GetProcAddress(h_adv, c"SetNamedSecurityInfoW".as_ptr().cast());
        let p_open_tok = GetProcAddress(h_adv, c"OpenProcessToken".as_ptr().cast());
        let p_tok_info = GetProcAddress(h_adv, c"GetTokenInformation".as_ptr().cast());
        let p_sid_str = GetProcAddress(h_adv, c"ConvertSidToStringSidW".as_ptr().cast());
        if p_sddl.is_null()
            || p_dacl.is_null()
            || p_set.is_null()
            || p_open_tok.is_null()
            || p_tok_info.is_null()
            || p_sid_str.is_null()
        {
            return Err("Failed to resolve advapi32 DACL APIs".to_string());
        }
        let convert_sddl: FnConvertSddl = std::mem::transmute(p_sddl);
        let get_dacl: FnGetDacl = std::mem::transmute(p_dacl);
        let set_named_sec: FnSetNamedSec = std::mem::transmute(p_set);
        let open_tok: FnOpenProcessToken = std::mem::transmute(p_open_tok);
        let get_tok_info: FnGetTokenInfo = std::mem::transmute(p_tok_info);
        let sid_to_str: FnConvertSidToStringSidW = std::mem::transmute(p_sid_str);

        let mut h_tok: *mut c_void = std::ptr::null_mut();
        let mut is_elevated = false;
        let mut owner_sid_str: Option<String> = None;

        if open_tok(GetCurrentProcess(), TOKEN_QUERY, &mut h_tok) != 0 && !h_tok.is_null() {
            let mut elev = TokenElevation {
                token_is_elevated: 0,
            };
            let mut ret_len = 0u32;
            if get_tok_info(
                h_tok,
                TOKEN_ELEVATION,
                &mut elev as *mut _ as *mut c_void,
                std::mem::size_of::<TokenElevation>() as u32,
                &mut ret_len,
            ) != 0
            {
                is_elevated = elev.token_is_elevated != 0;
            }
            if !is_elevated {
                let mut needed = 0u32;
                let _ = get_tok_info(h_tok, TOKEN_USER, std::ptr::null_mut(), 0, &mut needed);
                if needed > 0 {
                    let mut buf = vec![0u8; needed as usize];
                    if get_tok_info(
                        h_tok,
                        TOKEN_USER,
                        buf.as_mut_ptr() as *mut c_void,
                        needed,
                        &mut needed,
                    ) != 0
                    {
                        let user = &*(buf.as_ptr() as *const SidAndAttributes);
                        let mut wide_ptr: *mut u16 = std::ptr::null_mut();
                        if sid_to_str(user.sid, &mut wide_ptr) != 0 && !wide_ptr.is_null() {
                            let mut len = 0usize;
                            while *wide_ptr.add(len) != 0 {
                                len += 1;
                            }
                            let slice = std::slice::from_raw_parts(wide_ptr, len);
                            owner_sid_str = Some(String::from_utf16_lossy(slice));
                            let _ = LocalFree(wide_ptr as *mut c_void);
                        }
                    }
                }
            }
            let _ = CloseHandle(h_tok);
        }

        // Elevated daemon/installer strictly locks to SYSTEM + BUILTIN\Administrators only.
        // Non-elevated dev/test execution additionally retains the current owner SID while stripping Users/Everyone.
        let sddl = if is_elevated {
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)".to_string()
        } else if let Some(sid) = owner_sid_str {
            format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{})", sid)
        } else {
            "D:P(A;;FA;;;SY)(A;;FA;;;BA)".to_string()
        };
        let sddl_w: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut p_sd: *mut c_void = std::ptr::null_mut();
        if convert_sddl(sddl_w.as_ptr(), 1, &mut p_sd, std::ptr::null_mut()) == 0 || p_sd.is_null() {
            return Err("ConvertStringSecurityDescriptorToSecurityDescriptorW failed".to_string());
        }

        let mut present = 0i32;
        let mut defaulted = 0i32;
        let mut p_dacl_ptr: *mut c_void = std::ptr::null_mut();
        if get_dacl(p_sd, &mut present, &mut p_dacl_ptr, &mut defaulted) == 0 || present == 0 {
            let _ = LocalFree(p_sd);
            return Err("GetSecurityDescriptorDacl failed".to_string());
        }

        let path_w: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let rc = set_named_sec(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            p_dacl_ptr,
            std::ptr::null_mut(),
        );
        let _ = LocalFree(p_sd);
        if rc != 0 {
            return Err(format!("SetNamedSecurityInfoW failed with Win32 error {}", rc));
        }
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
fn seal_platform_secret_bytes(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    Ok(plaintext.to_vec())
}

#[cfg(not(target_os = "windows"))]
fn unseal_platform_secret_bytes(ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    Ok(ciphertext.to_vec())
}
