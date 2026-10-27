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
    status::{
        AuthMethod, AuthResult, LockoutState, OperatorAuthenticator, OperatorCredentials,
        KILLCHAIN_ISOLATE_TOKEN, KILLCHAIN_RESTORE_TOKEN,
    },
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
    fn verify_tier1_master_token(&self, candidate: &str) -> bool {
        let trimmed = candidate.trim();
        if trimmed.is_empty() {
            return false;
        }

        // Predefined emergency tokens
        if constant_time_eq(trimmed, KILLCHAIN_RESTORE_TOKEN)
            || constant_time_eq(trimmed, KILLCHAIN_ISOLATE_TOKEN)
        {
            return true;
        }

        // Custom configured master token
        if let Some(ref master) = self.custom_master_token {
            if !master.trim().is_empty() && constant_time_eq(trimmed, master.trim()) {
                return true;
            }
        }

        // Environment master token
        if let Ok(env_master) = std::env::var("KILLSWITCH_MASTER_TOKEN") {
            if !env_master.trim().is_empty() && constant_time_eq(trimmed, env_master.trim()) {
                return true;
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
                                if !clean.is_empty()
                                    && (constant_time_eq(&computed_b3, clean)
                                        || constant_time_eq(&computed_sha, clean)
                                        || constant_time_eq(trimmed, clean))
                                {
                                    return true;
                                }
                            }
                        }
                    }
                } else {
                    // Plain text hash file
                    let clean = content.trim();
                    if !clean.is_empty()
                        && (constant_time_eq(&computed_b3, clean)
                            || constant_time_eq(&computed_sha, clean)
                            || constant_time_eq(trimmed, clean))
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

    #[test]
    fn test_tier1_master_token_bypass_and_lockout_reset() {
        let auth = OperatorAuthManager::new(None, None);

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

        // Operator supplies master bypass phrase
        let master_creds = OperatorCredentials {
            operator_id: "admin".to_string(),
            auth_token: None,
            password: None,
            caller_pid: Some(5000),
            confirmation_phrase: Some(KILLCHAIN_RESTORE_TOKEN.to_string()),
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
}
