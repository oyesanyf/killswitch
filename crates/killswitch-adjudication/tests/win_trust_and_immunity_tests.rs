use killswitch_adjudication::immunity::{
    get_process_ancestry_chain, inspect_process_lineage, MAX_ANCESTRY_DEPTH,
};
use killswitch_adjudication::inventory::{
    get_protected_local_binary_hashes, is_protected_local_binary_hash,
    register_protected_binary_hash,
};
use killswitch_adjudication::win_trust::{
    clear_authenticode_cache, get_cached_authenticode_status, invalidate_cache_entry,
    is_trusted_vendor, is_untrusted_writable_location, verify_binary_cryptographic_trust,
    AUTHENTICODE_CACHE_TTL,
};
use killswitch_types::adjudication::{BinaryTrustVerdict, VetoReason};
use std::path::Path;
use std::time::Duration;

#[test]
fn test_wintrust_cache_ttl_and_invalidation() {
    assert_eq!(AUTHENTICODE_CACHE_TTL, Duration::from_secs(300));

    let path = "C:\\Windows\\System32\\calc.exe";
    let status1 = get_cached_authenticode_status(path);
    let status2 = get_cached_authenticode_status(path);
    assert_eq!(status1, status2);

    invalidate_cache_entry(path);
    clear_authenticode_cache();
}

#[test]
fn test_untrusted_writable_location_rejections() {
    // Windows temp / download directories
    assert!(is_untrusted_writable_location("C:\\Users\\Alice\\AppData\\Local\\Temp\\dropper.exe"));
    assert!(is_untrusted_writable_location("C:\\Users\\Alice\\Downloads\\installer.exe"));
    assert!(is_untrusted_writable_location("C:\\Users\\Public\\mal.exe"));
    assert!(is_untrusted_writable_location("C:\\ProgramData\\Temp\\tool.exe"));
    assert!(is_untrusted_writable_location("D:\\projects\\target\\debug\\binary.exe"));

    // Linux / macOS temp directories
    assert!(is_untrusted_writable_location("/tmp/payload"));
    assert!(is_untrusted_writable_location("/var/tmp/rootkit"));
    assert!(is_untrusted_writable_location("/dev/shm/stage"));
    assert!(is_untrusted_writable_location("/users/public/tool"));

    // Trusted system paths must not be marked untrusted
    assert!(!is_untrusted_writable_location("C:\\Windows\\System32\\svchost.exe"));
    assert!(!is_untrusted_writable_location("C:\\Program Files\\Git\\bin\\git.exe"));
    assert!(!is_untrusted_writable_location("/bin/ls"));
    assert!(!is_untrusted_writable_location("/usr/bin/cargo"));
}

#[test]
fn test_trusted_vendor_whitelist() {
    assert!(is_trusted_vendor("Microsoft Windows"));
    assert!(is_trusted_vendor("Microsoft Corporation"));
    assert!(is_trusted_vendor("Rust Project Developers"));
    assert!(is_trusted_vendor("Git for Windows"));
    assert!(is_trusted_vendor("Google LLC"));
    assert!(is_trusted_vendor("Apple Inc."));
    assert!(!is_trusted_vendor("Random Malware Author"));
    assert!(!is_trusted_vendor("Cryptominer Co."));
}

#[test]
fn test_verify_binary_cryptographic_trust_fail_closed_on_nonexistent() {
    let p = Path::new("C:\\NonExistentPath\\DefinitelyNotExist_12345.exe");
    let verdict = verify_binary_cryptographic_trust(p);
    assert!(!verdict.is_trusted());
    assert!(verdict.is_untrusted());
    match verdict {
        BinaryTrustVerdict::UntrustedIoError { error } => {
            assert!(error.contains("does not exist"));
        }
        _ => panic!("Expected UntrustedIoError"),
    }
}

#[test]
fn test_critical_system_pid_direct_immunity() {
    // Kernel PID 0 and 4
    let v0 = inspect_process_lineage(0, Some("system"));
    assert!(v0.is_immune());
    assert_eq!(v0.to_veto_reason(), Some(VetoReason::CriticalSystemPid));

    let v4 = inspect_process_lineage(4, Some("system"));
    assert!(v4.is_immune());
    assert_eq!(v4.to_veto_reason(), Some(VetoReason::CriticalSystemPid));

    // Self PID is always immune (preventing self-freeze)
    let v_self = inspect_process_lineage(std::process::id(), Some("killswitch-test"));
    assert!(v_self.is_immune());

    // Canonical Windows system binaries
    let v_svc = inspect_process_lineage(1000, Some("svchost.exe"));
    assert!(v_svc.is_immune());

    let v_lsass = inspect_process_lineage(1004, Some("lsass.exe"));
    assert!(v_lsass.is_immune());

    let v_exp = inspect_process_lineage(1008, Some("explorer.exe"));
    assert!(v_exp.is_immune());

    // Canonical developer tools
    let v_cargo = inspect_process_lineage(2000, Some("cargo.exe"));
    assert!(v_cargo.is_immune());

    let v_rustc = inspect_process_lineage(2004, Some("rustc.exe"));
    assert!(v_rustc.is_immune());

    let v_code = inspect_process_lineage(2008, Some("code.exe"));
    assert!(v_code.is_immune());
}

#[test]
fn test_ancestry_traversal_depth_5_limit() {
    assert_eq!(MAX_ANCESTRY_DEPTH, 5);

    let current_pid = std::process::id();
    let ancestry = get_process_ancestry_chain(current_pid);
    assert!(ancestry.len() <= MAX_ANCESTRY_DEPTH);

    // Current process inspection should terminate safely without hanging
    let verdict = inspect_process_lineage(current_pid, Some("test_runner.exe"));
    assert!(verdict.is_immune());
}

#[test]
fn test_protected_local_binary_hash_inventory() {
    let inventory = get_protected_local_binary_hashes();
    assert!(!inventory.is_empty()); // Pre-populated at initialization

    let custom_hash = "abcdef9999888877776666555544443333222211110000aaaabbbbccccdddd00";
    assert!(!is_protected_local_binary_hash(custom_hash));

    register_protected_binary_hash(custom_hash);
    assert!(is_protected_local_binary_hash(custom_hash));
    assert!(is_protected_local_binary_hash(&custom_hash.to_uppercase()));

    // Empty or whitespace hashes return false
    assert!(!is_protected_local_binary_hash(""));
    assert!(!is_protected_local_binary_hash("   "));
}
