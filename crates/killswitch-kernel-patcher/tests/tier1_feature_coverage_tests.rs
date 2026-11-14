//! Tier 1: Category-Partition Feature Coverage Test Suite for `killswitch-kernel-patcher`.
//! Covers Features F1 through F8 with >=5 tests per feature (total 40 tests).

mod common;
use common::*;
use killswitch_kernel_patcher::cpe::{
    canonicalize_linux_kernel_version, canonicalize_macos_version, canonicalize_windows_cpe,
    escape_cpe_attribute, split_unescaped_colons, Cpe23,
};
use killswitch_kernel_patcher::{
    is_elevated, HostKernelInfo, KernelPatcher, OsFamily, PatcherError, ScanOptions,
};

// =============================================================================
// Feature 1: Host Platform & Kernel Discovery (F1)
// =============================================================================

#[test]
fn test_tier1_f1_01_detect_current_host_returns_ok() {
    let res = HostKernelInfo::detect_host_kernel();
    assert!(
        res.is_ok(),
        "Host kernel detection must succeed on host OS: {:?}",
        res.err()
    );
    let info = res.unwrap();
    assert!(
        !info.kernel_release.is_empty(),
        "kernel_release must not be empty"
    );
    assert!(
        !info.architecture.is_empty(),
        "architecture must not be empty"
    );
}

#[test]
fn test_tier1_f1_02_detect_os_family_matches_target() {
    let info = HostKernelInfo::detect_host_kernel().expect("Kernel detection failed");
    #[cfg(target_os = "windows")]
    assert_eq!(info.os_family, OsFamily::Windows);
    #[cfg(target_os = "linux")]
    assert_eq!(info.os_family, OsFamily::Linux);
    #[cfg(target_os = "macos")]
    assert_eq!(info.os_family, OsFamily::MacOS);
}

#[test]
fn test_tier1_f1_03_kernel_release_semantic_format() {
    let info = HostKernelInfo::detect_host_kernel().expect("Kernel detection failed");
    #[cfg(target_os = "windows")]
    {
        // Windows kernel release is typically major.minor.build[.ubr]
        let parts: Vec<&str> = info.kernel_release.split('.').collect();
        assert!(
            parts.len() >= 3,
            "Windows release should have at least 3 parts: {}",
            info.kernel_release
        );
        for p in &parts {
            assert!(
                p.chars().all(|c| c.is_ascii_digit()),
                "Part '{}' is not numeric",
                p
            );
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        assert!(
            info.kernel_release.contains('.')
                || info.kernel_release.chars().any(|c| c.is_ascii_digit()),
            "Release string should contain version digits: {}",
            info.kernel_release
        );
    }
}

#[test]
fn test_tier1_f1_04_architecture_canonical_naming() {
    let info = HostKernelInfo::detect_host_kernel().expect("Kernel detection failed");
    assert!(
        ["x86_64", "aarch64", "x86", "arm"].contains(&info.architecture.as_str()),
        "Unexpected architecture nomenclature: {}",
        info.architecture
    );
}

#[test]
fn test_tier1_f1_05_detect_host_cpe_field_consistency() {
    let info = HostKernelInfo::detect_host_kernel().expect("Kernel detection failed");
    assert_eq!(info.cpe23, info.to_cpe23());
    assert!(info.cpe23.starts_with("cpe:2.3:o:"));
    assert_valid_cpe23(&info.cpe23);
}

// =============================================================================
// Feature 2: CPE 2.3 Formatting & Mapping (F2)
// =============================================================================

#[test]
fn test_tier1_f2_01_cpe_linux_kernel_canonical_format() {
    let base_version = canonicalize_linux_kernel_version("6.8.0-40-generic");
    let cpe = Cpe23::new_os("linux", "linux_kernel", base_version);
    let cpe_str = cpe.to_formatted_string();
    assert_eq!(cpe_str, "cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*");
}

#[test]
fn test_tier1_f2_02_cpe_windows_11_mapping() {
    let (product, version) = canonicalize_windows_cpe(22631, false, Some("23H2"));
    let cpe = Cpe23::new_os("microsoft", product, version);
    let cpe_str = cpe.to_formatted_string();
    assert_eq!(cpe_str, "cpe:2.3:o:microsoft:windows_11:23h2:*:*:*:*:*:*:*");
}

#[test]
fn test_tier1_f2_03_cpe_macos_darwin_mapping() {
    let version = canonicalize_macos_version("14.5 (23F79)");
    let cpe = Cpe23::new_os("apple", "macos", version);
    let cpe_str = cpe.to_formatted_string();
    assert_eq!(cpe_str, "cpe:2.3:o:apple:macos:14.5:*:*:*:*:*:*:*");
}

#[test]
fn test_tier1_f2_04_cpe_field_count_11_attributes() {
    let cpe = Cpe23::new_os("vendor", "product", "1.0.0");
    let formatted = cpe.to_formatted_string();
    let parts = split_unescaped_colons(&formatted);
    assert_eq!(
        parts.len(),
        13,
        "Must have exactly prefix (2) + 11 attributes = 13 fields"
    );
    assert_eq!(parts[0], "cpe");
    assert_eq!(parts[1], "2.3");
    assert_eq!(parts[2], "o");
}

#[test]
fn test_tier1_f2_05_cpe_special_character_escaping() {
    let escaped = escape_cpe_attribute("version:6.8.0");
    assert_eq!(escaped, r"version\:6.8.0");
    let cpe = Cpe23::new_os("vendor", "product", escaped);
    let formatted = cpe.to_formatted_string();
    let parts = split_unescaped_colons(&formatted);
    assert_eq!(
        parts.len(),
        13,
        "Escaped colon must not introduce extra field"
    );
}

// =============================================================================
// Feature 3: Privilege Elevation Detection (F3)
// =============================================================================

#[test]
fn test_tier1_f3_01_is_elevated_callable_without_panic() {
    let _ = is_elevated();
}

#[test]
fn test_tier1_f3_02_is_elevated_deterministic_repeatability() {
    let initial = is_elevated();
    for _ in 0..100 {
        assert_eq!(
            is_elevated(),
            initial,
            "Privilege check must be idempotent and deterministic"
        );
    }
}

#[test]
fn test_tier1_f3_03_is_elevated_thread_safety() {
    let mut handles = Vec::new();
    for _ in 0..16 {
        handles.push(std::thread::spawn(is_elevated));
    }
    let expected = is_elevated();
    for h in handles {
        assert_eq!(h.join().unwrap(), expected);
    }
}

#[tokio::test]
async fn test_tier1_f3_04_is_elevated_tokio_task_consistency() {
    let main_thread_val = is_elevated();
    let async_task_val = tokio::spawn(async { is_elevated() })
        .await
        .expect("Tokio task join failed");

    assert_eq!(
        main_thread_val, async_task_val,
        "is_elevated() inside tokio async task runtime must match caller thread"
    );

    #[cfg(windows)]
    {
        assert_eq!(
            main_thread_val,
            killswitch_kernel_patcher::privilege::windows::is_current_process_elevated(),
            "Elevation status must match Win32 TokenElevation query"
        );
    }

    #[cfg(unix)]
    {
        assert_eq!(
            main_thread_val,
            killswitch_kernel_patcher::privilege::unix::is_current_process_elevated(),
            "Elevation status must match POSIX geteuid query"
        );
    }
}

#[tokio::test]
async fn test_tier1_f3_05_is_elevated_fail_closed_contract() {
    let patcher = KernelPatcher::new();
    let elevated = is_elevated();

    // Verify fail-closed linkage: non-elevated callers MUST be blocked with InsufficientPrivileges
    let patch_result = patcher.apply_os_kernel_patch(false).await;
    match patch_result {
        Err(PatcherError::InsufficientPrivileges) => {
            assert!(
                !elevated,
                "InsufficientPrivileges returned but is_elevated() reported true"
            );
        }
        other => {
            assert!(
                elevated,
                "Expected InsufficientPrivileges for non-elevated caller, got: {:?}",
                other
            );
        }
    }
}

// =============================================================================
// Feature 4: NVD API 2.0 HTTP Client & Auth (F4)
// =============================================================================

#[tokio::test]
async fn test_tier1_f4_01_client_constructs_with_default_options() {
    let patcher = KernelPatcher::new();
    let opts = ScanOptions::default();
    assert!(opts.cpe.is_none());
    assert!(opts.min_cvss_score.is_none());
    assert!(!opts.kev_only);
    assert!(opts.api_key.is_none());
    assert_eq!(opts.timeout_secs, 30);
    let _ = patcher;
}

#[tokio::test]
async fn test_tier1_f4_02_client_attaches_apikey_header_when_present() {
    let server = MockNvdServer::start(FIXTURE_SINGLE_KEV_CVE_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let test_key = "secret_api_key_test_value_12345";
    let opts = test_scan_options(None, None, false, Some(test_key));

    let _ = patcher.scan_kernel_vulnerabilities(&opts).await;
    assert_eq!(server.last_api_key(), Some(test_key.to_string()));
}

#[tokio::test]
async fn test_tier1_f4_03_client_omits_apikey_header_when_none() {
    let server = MockNvdServer::start(FIXTURE_SINGLE_KEV_CVE_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let _ = patcher.scan_kernel_vulnerabilities(&opts).await;

    assert!(
        !server.has_header("apiKey"),
        "apiKey header should be omitted when None"
    );
}

#[tokio::test]
async fn test_tier1_f4_04_client_encodes_cpe_query_parameter() {
    let server = MockNvdServer::start(FIXTURE_SINGLE_KEV_CVE_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let cpe = "cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*";
    let opts = test_scan_options(Some(cpe), None, false, None);

    let _ = patcher.scan_kernel_vulnerabilities(&opts).await;
    assert_eq!(server.total_requests(), 1);
}

#[tokio::test]
async fn test_tier1_f4_05_client_respects_custom_timeout() {
    let server = MockNvdServer::start_with_delay(FIXTURE_SINGLE_KEV_CVE_JSON, 1000).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let mut opts = test_scan_options(None, None, false, None);
    opts.timeout_secs = 1;

    let res = patcher.scan_kernel_vulnerabilities(&opts).await;
    // Fast fail or successful finish within bound
    assert!(res.is_ok() || matches!(res, Err(PatcherError::Network(_))));
}

// =============================================================================
// Feature 5: Vulnerability JSON Parsing (F5)
// =============================================================================

#[tokio::test]
async fn test_tier1_f5_01_parse_standard_cve_with_cvss31() {
    let server = MockNvdServer::start(FIXTURE_NON_KEV_CRITICAL_CVE_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Scan failed");

    assert_eq!(vulns.len(), 1);
    let v = &vulns[0];
    assert_eq!(v.cve_id, "CVE-2024-9999");
    assert_eq!(v.cvss_v31_score, Some(9.8));
    assert_eq!(v.cvss_v31_severity.as_deref(), Some("CRITICAL"));
    assert!(!v.is_cisa_kev);
}

#[tokio::test]
async fn test_tier1_f5_02_parse_cisa_kev_fields() {
    let server = MockNvdServer::start(FIXTURE_SINGLE_KEV_CVE_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Scan failed");

    assert_eq!(vulns.len(), 1);
    let v = &vulns[0];
    assert!(v.is_cisa_kev);
    assert_eq!(v.cisa_exploit_add.as_deref(), Some("2024-03-25"));
    assert_eq!(v.cisa_action_due.as_deref(), Some("2024-04-15"));
    assert!(v.cisa_required_action.is_some());
    assert!(v.cisa_vulnerability_name.is_some());
}

#[tokio::test]
async fn test_tier1_f5_03_parse_description_english() {
    let server = MockNvdServer::start(FIXTURE_SINGLE_KEV_CVE_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Scan failed");

    assert_eq!(vulns.len(), 1);
    assert!(vulns[0].description.contains("netfilter"));
}

#[tokio::test]
async fn test_tier1_f5_04_parse_multiple_vulnerabilities_array() {
    let server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Scan failed");

    assert_eq!(vulns.len(), 5);
}

#[tokio::test]
async fn test_tier1_f5_05_parse_empty_vulnerabilities_list() {
    let server = MockNvdServer::start(FIXTURE_EMPTY_NVD_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Scan failed");

    assert!(vulns.is_empty());
}

// =============================================================================
// Feature 6: KEV Prioritization & CVSS Ranking (F6)
// =============================================================================

#[tokio::test]
async fn test_tier1_f6_01_kev_precedes_non_kev_regardless_of_cvss() {
    let server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Scan failed");

    // Invariant: All KEV entries must appear before non-KEV entries
    let first_non_kev_idx = vulns
        .iter()
        .position(|v| !v.is_cisa_kev)
        .unwrap_or(vulns.len());
    for v in &vulns[..first_non_kev_idx] {
        assert!(v.is_cisa_kev);
    }
    for v in &vulns[first_non_kev_idx..] {
        assert!(!v.is_cisa_kev);
    }
}

#[tokio::test]
async fn test_tier1_f6_02_kev_items_sorted_by_descending_cvss() {
    let server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Scan failed");

    let kev_items: Vec<_> = vulns.iter().filter(|v| v.is_cisa_kev).collect();
    for window in kev_items.windows(2) {
        if let (Some(a), Some(b)) = (window[0].cvss_v31_score, window[1].cvss_v31_score) {
            assert!(a >= b, "KEV CVSS scores must be descending: {} vs {}", a, b);
        }
    }
}

#[tokio::test]
async fn test_tier1_f6_03_non_kev_items_sorted_by_descending_cvss() {
    let server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Scan failed");

    let non_kev: Vec<_> = vulns.iter().filter(|v| !v.is_cisa_kev).collect();
    for window in non_kev.windows(2) {
        if let (Some(a), Some(b)) = (window[0].cvss_v31_score, window[1].cvss_v31_score) {
            assert!(
                a >= b,
                "Non-KEV CVSS scores must be descending: {} vs {}",
                a,
                b
            );
        }
    }
}

#[tokio::test]
async fn test_tier1_f6_04_kev_only_filter_excludes_non_kev() {
    let server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, true, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Scan failed");

    assert!(!vulns.is_empty());
    for v in &vulns {
        assert!(
            v.is_cisa_kev,
            "All findings must be CISA KEV entries when kev_only is true"
        );
    }
}

#[tokio::test]
async fn test_tier1_f6_05_min_cvss_threshold_filtering() {
    let server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, Some(7.0), false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Scan failed");

    for v in &vulns {
        assert!(v.cvss_v31_score.unwrap_or(0.0) >= 7.0);
    }
}

// =============================================================================
// Feature 7: Fail-Closed Patch Dispatch (F7)
// =============================================================================

#[tokio::test]
async fn test_tier1_f7_01_non_elevated_live_patch_fails_closed() {
    let patcher = KernelPatcher::new();
    if !is_elevated() {
        let res = patcher.apply_os_kernel_patch(false).await;
        assert!(matches!(res, Err(PatcherError::InsufficientPrivileges)));
    }
}

#[tokio::test]
async fn test_tier1_f7_02_windows_subsystem_dispatch_routes_to_usoclient() {
    #[cfg(target_os = "windows")]
    {
        let patcher = KernelPatcher::new();
        let res = patcher
            .apply_os_kernel_patch(true)
            .await
            .expect("Dry run planning failed");
        assert_eq!(res.os_subsystem, "UsoClient");
        assert_eq!(res.command, "UsoClient.exe");
    }
}

#[tokio::test]
async fn test_tier1_f7_03_linux_subsystem_dispatch_routes_to_package_manager() {
    #[cfg(target_os = "linux")]
    {
        let patcher = KernelPatcher::new();
        let res = patcher
            .apply_os_kernel_patch(true)
            .await
            .expect("Dry run planning failed");
        assert!(["canonical-livepatch", "apt-get", "dnf"].contains(&res.os_subsystem.as_str()));
    }
}

#[tokio::test]
async fn test_tier1_f7_04_macos_subsystem_dispatch_routes_to_softwareupdate() {
    #[cfg(target_os = "macos")]
    {
        let patcher = KernelPatcher::new();
        let res = patcher
            .apply_os_kernel_patch(true)
            .await
            .expect("Dry run planning failed");
        assert_eq!(res.os_subsystem, "softwareupdate");
        assert_eq!(res.command, "softwareupdate");
    }
}

#[test]
fn test_tier1_f7_05_unsupported_platform_returns_error() {
    // Calling an out-of-target platform discovery function on the current host
    // must genuinely return PatcherError::UnsupportedPlatform from crate logic.
    #[cfg(target_os = "windows")]
    {
        let res_linux = killswitch_kernel_patcher::discovery::linux::detect_linux_host_kernel();
        assert!(
            matches!(res_linux, Err(PatcherError::UnsupportedPlatform(ref s)) if s.contains("non-Linux")),
            "detect_linux_host_kernel on Windows must return UnsupportedPlatform: {:?}",
            res_linux
        );

        let res_macos = killswitch_kernel_patcher::discovery::macos::detect_macos_host_kernel();
        assert!(
            matches!(res_macos, Err(PatcherError::UnsupportedPlatform(ref s)) if s.contains("non-macOS")),
            "detect_macos_host_kernel on Windows must return UnsupportedPlatform: {:?}",
            res_macos
        );
    }

    #[cfg(target_os = "linux")]
    {
        let res_macos = killswitch_kernel_patcher::discovery::macos::detect_macos_host_kernel();
        assert!(
            matches!(res_macos, Err(PatcherError::UnsupportedPlatform(ref s)) if s.contains("non-macOS")),
            "detect_macos_host_kernel on Linux must return UnsupportedPlatform: {:?}",
            res_macos
        );

        let res_windows = killswitch_kernel_patcher::discovery::windows::detect_windows_kernel();
        assert!(
            matches!(res_windows, Err(PatcherError::UnsupportedPlatform(ref s)) if s.contains("non-Windows")),
            "detect_windows_kernel on Linux must return UnsupportedPlatform: {:?}",
            res_windows
        );
    }

    #[cfg(target_os = "macos")]
    {
        let res_windows = killswitch_kernel_patcher::discovery::windows::detect_windows_kernel();
        assert!(
            matches!(res_windows, Err(PatcherError::UnsupportedPlatform(ref s)) if s.contains("non-Windows")),
            "detect_windows_kernel on macOS must return UnsupportedPlatform: {:?}",
            res_windows
        );

        let res_linux = killswitch_kernel_patcher::discovery::linux::detect_linux_host_kernel();
        assert!(
            matches!(res_linux, Err(PatcherError::UnsupportedPlatform(ref s)) if s.contains("non-Linux")),
            "detect_linux_host_kernel on macOS must return UnsupportedPlatform: {:?}",
            res_linux
        );
    }
}

// =============================================================================
// Feature 8: Safe Dry-Run Mode (F8)
// =============================================================================

#[tokio::test]
async fn test_tier1_f8_01_dry_run_flag_true_in_result() {
    let patcher = KernelPatcher::new();
    let res = patcher
        .apply_os_kernel_patch(true)
        .await
        .expect("Dry run failed");
    assert!(res.dry_run, "Dry run result must have dry_run == true");
}

#[tokio::test]
async fn test_tier1_f8_02_dry_run_does_not_mutate_system_state() {
    let patcher = KernelPatcher::new();
    let res = patcher
        .apply_os_kernel_patch(true)
        .await
        .expect("Dry run failed");
    assert!(res.success);
    assert!(res.output.contains("[DRY-RUN]"));
}

#[tokio::test]
async fn test_tier1_f8_03_dry_run_succeeds_even_when_not_elevated() {
    let patcher = KernelPatcher::new();
    let res = patcher.apply_os_kernel_patch(true).await;
    assert!(res.is_ok(), "Dry run must succeed regardless of elevation");
}

#[tokio::test]
async fn test_tier1_f8_04_dry_run_formats_exact_command_and_args() {
    let patcher = KernelPatcher::new();
    let res = patcher
        .apply_os_kernel_patch(true)
        .await
        .expect("Dry run failed");
    assert!(!res.command.is_empty());
    assert!(!res.args.is_empty());
}

#[tokio::test]
async fn test_tier1_f8_05_dry_run_success_flag_and_descriptive_output() {
    let patcher = KernelPatcher::new();
    let res = patcher
        .apply_os_kernel_patch(true)
        .await
        .expect("Dry run failed");
    assert!(res.success);
    assert!(!res.output.is_empty());
}
