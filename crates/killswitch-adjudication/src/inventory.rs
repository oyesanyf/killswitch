//! In-memory Protected Local Binary BLAKE3 Hash Inventory.
//!
//! Maintains a concurrent `DashSet<String>` of known-trusted system and developer binaries.
//! Any peer proposal or candidate threat targeting a binary matching this inventory is
//! deterministically vetoed and emits a `ByzantineKillSwitchFraudProof`.

use dashmap::DashSet;
use std::sync::OnceLock;
use tracing::debug;

/// Global concurrent in-memory set of protected binary BLAKE3 digests (lowercase hex).
static PROTECTED_LOCAL_BINARY_HASHES: OnceLock<DashSet<String>> = OnceLock::new();

/// Retrieve the protected local binary hash inventory reference.
pub fn get_protected_local_binary_hashes() -> &'static DashSet<String> {
    PROTECTED_LOCAL_BINARY_HASHES.get_or_init(init_protected_local_binary_hashes)
}

/// Initialize the protected local binary hash inventory from verified host binaries.
fn init_protected_local_binary_hashes() -> DashSet<String> {
    let set = DashSet::new();

    // 1. Hash current running executable and companion libraries in its directory
    // Enforces symlink rejection and blocks binaries in untrusted writable locations
    if let Ok(raw_exe) = std::env::current_exe() {
        if let Ok(exe_path) = raw_exe.canonicalize() {
            let is_untrusted = crate::win_trust::is_untrusted_writable_location(&exe_path.to_string_lossy());
            if !raw_exe.is_symlink() && !exe_path.is_symlink() && !is_untrusted && exe_path.is_file() {
                if let Ok(bytes) = std::fs::read(&exe_path) {
                    let digest = blake3::hash(&bytes).to_hex().to_string().to_ascii_lowercase();
                    debug!("Protected inventory: registered self executable hash {}", digest);
                    set.insert(digest);
                }
                if let Some(parent) = exe_path.parent() {
                    if let Ok(entries) = std::fs::read_dir(parent) {
                        for entry in entries.flatten().take(32) {
                            let p = entry.path();
                            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                            if (ext.eq_ignore_ascii_case("exe")
                                || ext.eq_ignore_ascii_case("dll")
                                || ext.eq_ignore_ascii_case("so")
                                || ext.eq_ignore_ascii_case("dylib"))
                                && p.is_file()
                            {
                                if let Ok(meta) = p.metadata() {
                                    if meta.len() > 0 && meta.len() <= 64 * 1024 * 1024 {
                                        if let Ok(bytes) = std::fs::read(&p) {
                                            let digest = blake3::hash(&bytes).to_hex().to_string().to_ascii_lowercase();
                                            set.insert(digest);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Discover and hash developer toolchains from standard paths
    let toolchain_bins = ["cargo", "rustc", "rustup"];
    for tool in &toolchain_bins {
        if let Ok(path) = which_tool(tool) {
            if path.is_file() {
                if let Ok(bytes) = std::fs::read(&path) {
                    let digest = blake3::hash(&bytes).to_hex().to_string().to_ascii_lowercase();
                    debug!("Protected inventory: registered toolchain {} hash {}", tool, digest);
                    set.insert(digest);
                }
            }
        }
    }

    // 3. Hash active running OS processes ONLY if cryptographically signed or catalog-verified on Windows
    #[cfg(target_os = "windows")]
    {
        use sysinfo::{ProcessRefreshKind, RefreshKind, System, UpdateKind};
        let sys = System::new_with_specifics(
            RefreshKind::new()
                .with_processes(ProcessRefreshKind::new().with_exe(UpdateKind::OnlyIfNotSet)),
        );
        for proc in sys.processes().values().take(64) {
            if let Some(exe) = proc.exe() {
                if exe.is_file() {
                    let exe_str = exe.to_string_lossy();
                    let auth_status = crate::win_trust::check_authenticode_status(&exe_str);
                    if auth_status.is_trusted()
                        || crate::win_trust::verify_windows_catalog_signature(&exe_str)
                    {
                        if let Ok(meta) = exe.metadata() {
                            if meta.len() > 0 && meta.len() <= 32 * 1024 * 1024 {
                                if let Ok(bytes) = std::fs::read(exe) {
                                    let digest = blake3::hash(&bytes).to_hex().to_string().to_ascii_lowercase();
                                    set.insert(digest);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    set
}

/// Helper to locate a tool in system PATH without invoking subprocesses.
fn which_tool(name: &str) -> Result<std::path::PathBuf, ()> {
    if let Ok(path_var) = std::env::var("PATH") {
        let separator = if cfg!(windows) { ';' } else { ':' };
        for dir in path_var.split(separator) {
            let base = std::path::Path::new(dir).join(name);
            if base.is_file() {
                return Ok(base);
            }
            if cfg!(windows) {
                let exe = base.with_extension("exe");
                if exe.is_file() {
                    return Ok(exe);
                }
            }
        }
    }
    Err(())
}

/// Register a known protected OS or developer binary BLAKE3 hash into the global inventory.
pub fn register_protected_binary_hash(hash_hex: &str) {
    let normalized = hash_hex.trim().to_ascii_lowercase();
    if !normalized.is_empty() {
        get_protected_local_binary_hashes().insert(normalized);
    }
}

/// Checks whether a given BLAKE3 hash matches a protected local operating system or developer binary.
pub fn is_protected_local_binary_hash(hash_hex: &str) -> bool {
    let normalized = hash_hex.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    get_protected_local_binary_hashes().contains(&normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inventory_registration_and_lookup() {
        let dummy_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(!is_protected_local_binary_hash(dummy_hash));

        register_protected_binary_hash(dummy_hash);
        assert!(is_protected_local_binary_hash(dummy_hash));
        assert!(is_protected_local_binary_hash(&dummy_hash.to_uppercase()));

        assert!(!is_protected_local_binary_hash(""));
        assert!(!is_protected_local_binary_hash("   "));
    }
}
