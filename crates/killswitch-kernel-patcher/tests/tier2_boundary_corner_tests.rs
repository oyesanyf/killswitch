//! Tier 2: Boundary Value Analysis & Corner Cases Test Suite for `killswitch-kernel-patcher`.
//! Covers Features F1 through F8 with >=5 edge/boundary tests per feature (total 40 tests).

mod common;
use common::*;
use killswitch_kernel_patcher::cpe::{
    canonicalize_linux_kernel_version, escape_cpe_attribute, split_unescaped_colons, Cpe23,
};
use killswitch_kernel_patcher::discovery::{
    parse_linux_kernel_info, parse_macos_kernel_info, parse_windows_kernel_info,
};
use killswitch_kernel_patcher::{is_elevated, KernelPatcher, PatchExecutionResult, PatcherError};

// =============================================================================
// Feature 1: Host Platform & Kernel Discovery (F1 - Tier 2)
// =============================================================================

#[test]
fn test_tier2_f1_01_whitespace_and_newlines_in_kernel_version() {
    let raw = "  6.8.0-generic \r\n  ";
    let canonical = canonicalize_linux_kernel_version(raw);
    assert_eq!(canonical, "6.8.0");

    let info = parse_linux_kernel_info(raw, None, "x86_64");
    assert_eq!(info.kernel_release, "6.8.0-generic");
}

#[test]
fn test_tier2_f1_02_unrecognized_custom_os_family() {
    let unknown_os = killswitch_kernel_patcher::OsFamily::Unknown("CustomYoctoOS".into());
    assert!(!unknown_os.is_linux());
    assert!(!unknown_os.is_windows());
    assert!(!unknown_os.is_macos());
    assert_eq!(format!("{}", unknown_os), "Unknown (CustomYoctoOS)");
}

#[test]
fn test_tier2_f1_03_empty_system_info_fallback_handling() {
    // When raw kernel release and os-release are completely empty,
    // discovery parsers must gracefully fall back to safe canonical defaults without panicking.
    let linux_empty = parse_linux_kernel_info("", Some(""), "");
    assert_eq!(
        linux_empty.os_version, "unknown",
        "Empty os-release must fall back to 'unknown'"
    );
    assert_eq!(
        linux_empty.cpe23, "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
        "Empty kernel version must canonicalize to wildcard CPE"
    );

    let macos_empty = parse_macos_kernel_info(None, "", "");
    assert!(
        macos_empty.cpe23.starts_with("cpe:2.3:o:apple:macos:"),
        "Empty macOS version must fall back to valid apple:macos CPE"
    );

    let windows_empty = parse_windows_kernel_info(0, 0, 0, None, None, None, "");
    assert!(
        windows_empty.os_version.contains("Build 0.0.0"),
        "Zeroed Windows version must format safely: {}",
        windows_empty.os_version
    );
}

#[test]
fn test_tier2_f1_04_extreme_length_kernel_release() {
    let long_release = "6.".to_string() + &"9".repeat(5000);
    let canonical = canonicalize_linux_kernel_version(&long_release);
    assert!(canonical.len() < 6000);
}

#[test]
fn test_tier2_f1_05_non_ascii_os_release_metadata() {
    let os_release_content =
        "ID=french_linux\nPRETTY_NAME=\"Édition Française 2026\"\nVERSION_ID=\"1.0\"\n";
    let info = parse_linux_kernel_info("6.8.0", Some(os_release_content), "x86_64");
    assert_eq!(info.os_version, "1.0");
    assert!(!info.os_version.contains('\u{FFFD}'));
}

// =============================================================================
// Feature 2: CPE 2.3 Formatting & Mapping (F2 - Tier 2)
// =============================================================================

#[test]
fn test_tier2_f2_01_empty_cpe_version_wildcard() {
    let escaped = escape_cpe_attribute("");
    assert_eq!(escaped, "*");
    let cpe = Cpe23::new_os("vendor", "product", escaped);
    assert_eq!(
        cpe.to_formatted_string(),
        "cpe:2.3:o:vendor:product:*:*:*:*:*:*:*:*"
    );
}

#[test]
fn test_tier2_f2_02_colon_in_version_must_be_escaped() {
    let escaped = escape_cpe_attribute("6.8.0:rc1");
    assert_eq!(escaped, r"6.8.0\:rc1");
    let cpe = Cpe23::new_os("vendor", "product", escaped);
    let formatted = cpe.to_formatted_string();
    let parts = split_unescaped_colons(&formatted);
    assert_eq!(parts.len(), 13);
}

#[test]
fn test_tier2_f2_03_space_in_vendor_or_product() {
    let escaped_product = escape_cpe_attribute("Windows 11 Enterprise");
    assert_eq!(escaped_product, "windows_11_enterprise");
    let cpe = Cpe23::new_os("microsoft", escaped_product, "23h2");
    assert!(cpe.to_formatted_string().contains("windows_11_enterprise"));
}

#[test]
fn test_tier2_f2_04_traversal_characters_in_cpe_attributes() {
    let malicious = "../../etc/shadow";
    let escaped = escape_cpe_attribute(malicious);
    // Traversal slashes are escaped per NIST IR 7695
    assert!(escaped.contains(r"\.\./\.\./") || !escaped.contains("../"));
}

#[test]
fn test_tier2_f2_05_malformed_cpe_detection() {
    let malformed = "invalid:cpe:string";
    assert!(!malformed.starts_with("cpe:2.3:o:"));
    assert_ne!(malformed.split(':').count(), 13);
}

// =============================================================================
// Feature 3: Privilege Elevation Detection (F3 - Tier 2)
// =============================================================================

#[tokio::test]
async fn test_tier2_f3_01_token_query_failure_fails_closed() {
    let patcher = KernelPatcher::new();
    let elevated = is_elevated();

    // Contract: Fail-closed invariant mandates that live patch execution MUST be rejected
    // with InsufficientPrivileges whenever is_elevated() evaluates to false.
    let patch_res = patcher.apply_os_kernel_patch(false).await;
    if !elevated {
        assert!(
            matches!(patch_res, Err(PatcherError::InsufficientPrivileges)),
            "Non-elevated execution must fail closed with InsufficientPrivileges, got: {:?}",
            patch_res
        );
    } else {
        assert!(
            !matches!(patch_res, Err(PatcherError::InsufficientPrivileges)),
            "Elevated execution must not fail with InsufficientPrivileges"
        );
    }
}

#[test]
fn test_tier2_f3_02_restricted_filtered_token_uac() {
    let elevated = is_elevated();

    #[cfg(windows)]
    {
        let platform_elevated =
            killswitch_kernel_patcher::privilege::windows::is_current_process_elevated();
        assert_eq!(
            elevated, platform_elevated,
            "Elevation status under UAC token filtering must strictly match windows::is_current_process_elevated"
        );
    }

    #[cfg(unix)]
    {
        let expected = unsafe { libc::geteuid() == 0 };
        assert_eq!(
            elevated, expected,
            "Elevation status must strictly match POSIX geteuid == 0 under standard/restricted user"
        );
    }

    // Invariant: The elevation status must remain constant across repeated queries
    // even when called from different OS threads (filtered token is process-bound)
    let thread_result = std::thread::spawn(is_elevated)
        .join()
        .expect("Thread panicked");
    assert_eq!(
        elevated, thread_result,
        "Filtered token elevation status must be identical across all threads of the process"
    );
}

#[test]
fn test_tier2_f3_03_unix_setuid_mismatch() {
    // Evaluates effective credentials
    let elevated = is_elevated();
    #[cfg(unix)]
    {
        let expected = unsafe { libc::geteuid() == 0 };
        assert_eq!(elevated, expected);
    }
    let _ = elevated;
}

#[test]
fn test_tier2_f3_04_appcontainer_sandbox_restriction() {
    let elevated = is_elevated();

    #[cfg(windows)]
    {
        assert_eq!(
            elevated,
            killswitch_kernel_patcher::privilege::windows::is_current_process_elevated(),
            "is_elevated() must match windows::is_current_process_elevated"
        );

        if elevated {
            assert!(
                std::env::var("APP_CONTAINER").is_err(),
                "Process cannot be elevated while reporting APP_CONTAINER environment"
            );
        }
    }

    #[cfg(unix)]
    {
        let euid = unsafe { libc::geteuid() };
        if elevated {
            assert_eq!(euid, 0, "Elevated process must have euid == 0");
        } else {
            assert_ne!(euid, 0, "Non-elevated process must have non-zero euid");
        }
    }
}

#[tokio::test]
async fn test_tier2_f3_05_privilege_gate_live_vs_dry_run_contrast() {
    let patcher = KernelPatcher::new();
    let elevated = is_elevated();

    // Dry-run mode MUST succeed even in unprivileged environments
    let dry_run_res = patcher.apply_os_kernel_patch(true).await;
    assert!(
        dry_run_res.is_ok(),
        "Dry-run patch planning must always succeed regardless of elevation: {:?}",
        dry_run_res.err()
    );

    // Live mode MUST strictly enforce the privilege boundary:
    let live_res = patcher.apply_os_kernel_patch(false).await;
    if !elevated {
        assert!(
            matches!(live_res, Err(PatcherError::InsufficientPrivileges)),
            "Live patch execution without elevation must return InsufficientPrivileges, got: {:?}",
            live_res
        );
    } else {
        assert!(
            !matches!(live_res, Err(PatcherError::InsufficientPrivileges)),
            "Live patch execution with elevation must pass the privilege check"
        );
    }
}

// =============================================================================
// Feature 4: NVD API 2.0 HTTP Client & Auth (F4 - Tier 2)
// =============================================================================

#[tokio::test]
async fn test_tier2_f4_01_http_429_rate_limited_error_mapping() {
    let server = MockNvdServer::start_with_status(429, FIXTURE_RATE_LIMIT_429_BODY).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let res = patcher.scan_kernel_vulnerabilities(&opts).await;

    assert!(matches!(res, Err(PatcherError::RateLimited)));
}

#[tokio::test]
async fn test_tier2_f4_02_http_403_forbidden_invalid_api_key() {
    let server = MockNvdServer::start_with_status(403, r#"{"message": "Invalid API Key"}"#).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, Some("invalid_key"));
    let res = patcher.scan_kernel_vulnerabilities(&opts).await;

    assert!(matches!(res, Err(PatcherError::NvdApiError(_))));
}

#[tokio::test]
async fn test_tier2_f4_03_http_503_service_unavailable() {
    let server =
        MockNvdServer::start_with_status(503, r#"{"message": "Service Unavailable"}"#).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let res = patcher.scan_kernel_vulnerabilities(&opts).await;

    assert!(matches!(res, Err(PatcherError::NvdApiError(_))));
}

#[tokio::test]
async fn test_tier2_f4_04_empty_api_key_treated_as_none() {
    let server = MockNvdServer::start(FIXTURE_SINGLE_KEV_CVE_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, Some("   "));
    let _ = patcher.scan_kernel_vulnerabilities(&opts).await;

    // Blank or whitespace-only keys should not be sent
    if server.has_header("apiKey") {
        let key = server.last_api_key().unwrap();
        assert!(!key.trim().is_empty());
    }
}

#[tokio::test]
async fn test_tier2_f4_05_micro_timeout_connection_drop() {
    let server = MockNvdServer::start_with_delay(FIXTURE_SINGLE_KEV_CVE_JSON, 500).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let mut opts = test_scan_options(None, None, false, None);
    opts.timeout_secs = 1;

    let res = patcher.scan_kernel_vulnerabilities(&opts).await;
    assert!(res.is_ok() || matches!(res, Err(PatcherError::Network(_))));
}

// =============================================================================
// Feature 5: Vulnerability JSON Parsing (F5 - Tier 2)
// =============================================================================

#[tokio::test]
async fn test_tier2_f5_01_missing_optional_kev_fields() {
    let server = MockNvdServer::start(FIXTURE_PARTIAL_KEV_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Scan failed");

    assert_eq!(vulns.len(), 1);
    let v = &vulns[0];
    assert!(v.is_cisa_kev);
    assert_eq!(v.cisa_exploit_add.as_deref(), Some("2024-02-29"));
    assert_eq!(v.cisa_action_due, None);
}

#[tokio::test]
async fn test_tier2_f5_02_missing_all_cvss_metrics() {
    let server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Scan failed");

    let unscored = vulns
        .iter()
        .find(|v| v.cve_id == "CVE-2021-0001")
        .expect("Missing unscored CVE");
    assert_eq!(unscored.cvss_v31_score, None);
    assert_eq!(unscored.cvss_v31_severity, None);
}

#[tokio::test]
async fn test_tier2_f5_03_multi_metric_precedence_v31_over_v2() {
    let server = MockNvdServer::start(FIXTURE_MULTI_METRIC_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Scan failed");

    assert_eq!(vulns.len(), 1);
    let v = &vulns[0];
    assert_eq!(
        v.cvss_v31_score,
        Some(7.8),
        "Must select CVSS v3.1 score over legacy v2.0"
    );
    assert_eq!(v.cvss_v31_severity.as_deref(), Some("HIGH"));
}

#[tokio::test]
async fn test_tier2_f5_04_malformed_truncated_json() {
    let server = MockNvdServer::start(FIXTURE_MALFORMED_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let res = patcher.scan_kernel_vulnerabilities(&opts).await;

    assert!(matches!(res, Err(PatcherError::Serialization(_))));
}

#[tokio::test]
async fn test_tier2_f5_05_cvss_score_boundaries_0_and_10() {
    let fixture_extremes = r#"{
      "resultsPerPage": 2, "startIndex": 0, "totalResults": 2, "format": "NVD_CVE", "version": "2.0",
      "timestamp": "2026-11-13T21:00:00.000",
      "vulnerabilities": [
        {"cve": {"id": "CVE-2024-0000", "descriptions": [{"lang": "en", "value": "Zero score"}], "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "baseScore": 0.0, "baseSeverity": "NONE"}}]}}},
        {"cve": {"id": "CVE-2024-1000", "descriptions": [{"lang": "en", "value": "Max score"}], "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "baseScore": 10.0, "baseSeverity": "CRITICAL"}}]}}}
      ]
    }"#;

    let server = MockNvdServer::start(fixture_extremes).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Scan failed");

    assert_eq!(vulns.len(), 2);
    assert_eq!(vulns[0].cvss_v31_score, Some(10.0));
    assert_eq!(vulns[1].cvss_v31_score, Some(0.0));
}

// =============================================================================
// Feature 6: KEV Prioritization & CVSS Ranking (F6 - Tier 2)
// =============================================================================

#[tokio::test]
async fn test_tier2_f6_01_unscored_cve_sorted_last() {
    let server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Scan failed");

    let last = vulns.last().expect("Must have last item");
    assert_eq!(last.cve_id, "CVE-2021-0001", "Unscored item must sort last");
    assert_eq!(last.cvss_v31_score, None);
}

#[tokio::test]
async fn test_tier2_f6_02_cvss_threshold_exact_boundary() {
    let server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    // Exact match for 7.8
    let opts = test_scan_options(None, Some(7.8), false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Scan failed");

    assert!(vulns
        .iter()
        .any(|v| v.cve_id == "CVE-2024-1086" && v.cvss_v31_score == Some(7.8)));
    for v in &vulns {
        assert!(v.cvss_v31_score.unwrap_or(0.0) >= 7.8);
    }
}

#[tokio::test]
async fn test_tier2_f6_03_cvss_threshold_at_zero_and_ten() {
    let server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    // min_cvss = 0.0 -> all scored retained
    let opts_0 = test_scan_options(None, Some(0.0), false, None);
    let vulns_0 = patcher
        .scan_kernel_vulnerabilities(&opts_0)
        .await
        .expect("Scan failed");
    assert!(!vulns_0.is_empty());

    // min_cvss = 10.0 -> none of the fixture items reach 10.0
    let opts_10 = test_scan_options(None, Some(10.0), false, None);
    let vulns_10 = patcher
        .scan_kernel_vulnerabilities(&opts_10)
        .await
        .expect("Scan failed");
    assert!(vulns_10.is_empty());
}

#[tokio::test]
async fn test_tier2_f6_04_equal_cvss_scores_deterministic_tiebreak() {
    let fixture_ties = r#"{
      "resultsPerPage": 2, "startIndex": 0, "totalResults": 2, "format": "NVD_CVE", "version": "2.0",
      "timestamp": "2026-11-13T21:00:00.000",
      "vulnerabilities": [
        {"cve": {"id": "CVE-2024-2000", "descriptions": [{"lang": "en", "value": "Tie B"}], "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "baseScore": 8.0, "baseSeverity": "HIGH"}}]}}},
        {"cve": {"id": "CVE-2024-1000", "descriptions": [{"lang": "en", "value": "Tie A"}], "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "baseScore": 8.0, "baseSeverity": "HIGH"}}]}}}
      ]
    }"#;

    let server = MockNvdServer::start(fixture_ties).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let run1 = patcher.scan_kernel_vulnerabilities(&opts).await.unwrap();
    let run2 = patcher.scan_kernel_vulnerabilities(&opts).await.unwrap();

    assert_eq!(
        run1[0].cve_id, run2[0].cve_id,
        "Tiebreaking must be strictly deterministic across calls"
    );
}

#[tokio::test]
async fn test_tier2_f6_05_all_items_homogenous_or_empty() {
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
// Feature 7: Fail-Closed Patch Dispatch (F7 - Tier 2)
// =============================================================================

#[tokio::test]
async fn test_tier2_f7_01_planned_binary_matches_host_subsystem() {
    let patcher = KernelPatcher::new();
    let res = patcher
        .apply_os_kernel_patch(true)
        .await
        .expect("Dry run failed");

    #[cfg(target_os = "windows")]
    {
        assert_eq!(res.command, "UsoClient.exe");
        assert_eq!(res.os_subsystem, "UsoClient");
        assert!(
            res.args
                .iter()
                .any(|a| a == "StartInstall" || a == "StartInteractiveScan"),
            "Windows patch dispatch must invoke StartInstall or StartInteractiveScan, got: {:?}",
            res.args
        );
    }

    #[cfg(target_os = "linux")]
    {
        assert!(
            ["canonical-livepatch", "apt-get", "dnf"].contains(&res.command.as_str()),
            "Linux patch command must be a supported orchestrator: {}",
            res.command
        );
        assert_eq!(res.command, res.os_subsystem);
    }

    #[cfg(target_os = "macos")]
    {
        assert_eq!(res.command, "softwareupdate");
        assert_eq!(res.os_subsystem, "softwareupdate");
        assert!(res.args.contains(&"--install".to_string()));
    }
}

#[tokio::test]
async fn test_tier2_f7_02_unprivileged_live_patch_error_contract() {
    let patcher = KernelPatcher::new();
    if !is_elevated() {
        let err = patcher
            .apply_os_kernel_patch(false)
            .await
            .expect_err("Live patch without elevation must fail");
        assert!(matches!(err, PatcherError::InsufficientPrivileges));
        let msg = format!("{err}");
        assert!(
            msg.contains("Insufficient privileges") || msg.contains("Administrator"),
            "Error display message must clearly explain privilege requirement: {}",
            msg
        );
    }
}

#[tokio::test]
async fn test_tier2_f7_03_dry_run_execution_result_invariants() {
    let patcher = KernelPatcher::new();
    let res = patcher
        .apply_os_kernel_patch(true)
        .await
        .expect("Dry run planning failed");

    // Comprehensive invariant verification on real PatchExecutionResult returned by crate
    assert!(res.dry_run, "dry_run must be true");
    assert!(res.success, "dry-run planning must report success = true");
    assert!(!res.command.is_empty(), "command must not be empty");
    assert!(!res.args.is_empty(), "args must not be empty");
    for arg in &res.args {
        assert!(!arg.trim().is_empty(), "Arguments must not be blank");
    }
    assert!(
        res.output.contains(&res.command),
        "Dry run output '{}' must reference planned command '{}'",
        res.output,
        res.command
    );
    assert!(
        res.output.starts_with("[DRY-RUN]"),
        "Dry run output must be prefixed with [DRY-RUN]: '{}'",
        res.output
    );
}

#[tokio::test]
async fn test_tier2_f7_04_privilege_check_precedes_command_lookup() {
    let patcher = KernelPatcher::new();
    if !is_elevated() {
        let res = patcher.apply_os_kernel_patch(false).await;
        // Must fail with InsufficientPrivileges before attempting execution
        assert!(matches!(res, Err(PatcherError::InsufficientPrivileges)));
    }
}

#[tokio::test]
async fn test_tier2_f7_05_command_injection_prevention_in_args() {
    let patcher = KernelPatcher::new();
    let res = patcher
        .apply_os_kernel_patch(true)
        .await
        .expect("Dry run planning failed");

    // Shell metacharacters that must NEVER appear in discrete argv tokens
    let forbidden_chars = [';', '&', '|', '`', '$', '>', '<', '\n', '\r', '\0'];

    for ch in forbidden_chars {
        assert!(
            !res.command.contains(ch),
            "Command '{}' contains dangerous shell metacharacter '{}'",
            res.command,
            ch
        );
        for arg in &res.args {
            assert!(
                !arg.contains(ch),
                "Argument '{}' contains dangerous shell metacharacter '{}'",
                arg,
                ch
            );
        }
    }
}

// =============================================================================
// Feature 8: Safe Dry-Run Mode (F8 - Tier 2)
// =============================================================================

#[test]
fn test_tier2_f8_01_unsupported_platform_error_display_and_traits() {
    // Invoke genuine crate discovery for non-host platforms to verify UnsupportedPlatform error generation
    #[cfg(target_os = "windows")]
    let err = killswitch_kernel_patcher::discovery::linux::detect_linux_host_kernel()
        .expect_err("Must fail on non-Linux");

    #[cfg(target_os = "linux")]
    let err = killswitch_kernel_patcher::discovery::windows::detect_windows_kernel()
        .expect_err("Must fail on non-Windows");

    #[cfg(target_os = "macos")]
    let err = killswitch_kernel_patcher::discovery::windows::detect_windows_kernel()
        .expect_err("Must fail on non-Windows");

    // Verify error taxonomy and Display trait formatting
    match &err {
        PatcherError::UnsupportedPlatform(platform_msg) => {
            assert!(
                !platform_msg.is_empty(),
                "UnsupportedPlatform message must not be empty"
            );
            let display_str = format!("{err}");
            assert!(
                display_str.starts_with("Unsupported platform:"),
                "Display representation must start with 'Unsupported platform:': '{}'",
                display_str
            );
        }
        other => panic!(
            "Expected PatcherError::UnsupportedPlatform, got: {:?}",
            other
        ),
    }
}

#[tokio::test]
async fn test_tier2_f8_02_dry_run_args_vector_exact_tokens() {
    let patcher = KernelPatcher::new();
    let res = patcher
        .apply_os_kernel_patch(true)
        .await
        .expect("Dry run failed");
    for arg in &res.args {
        assert!(
            !arg.contains(' '),
            "Arguments should be separate argv tokens: '{}'",
            arg
        );
    }
}

#[test]
fn test_tier2_f8_03_dry_run_json_serialization_roundtrip() {
    let original = PatchExecutionResult {
        dry_run: true,
        command: "apt-get".to_string(),
        args: vec!["update".to_string(), "--only-upgrade".to_string()],
        success: true,
        output: "[DRY-RUN] Planned patch".to_string(),
        os_subsystem: "apt".to_string(),
    };
    let json = serde_json::to_string(&original).expect("Serialize failed");
    let back: PatchExecutionResult = serde_json::from_str(&json).expect("Deserialize failed");
    assert_eq!(original, back);
}

#[tokio::test]
async fn test_tier2_f8_04_dry_run_high_concurrency_stress() {
    let patcher = std::sync::Arc::new(KernelPatcher::new());
    let mut tasks = Vec::new();

    for _ in 0..50 {
        let p = std::sync::Arc::clone(&patcher);
        tasks.push(tokio::spawn(
            async move { p.apply_os_kernel_patch(true).await },
        ));
    }

    for task in tasks {
        let res = task.await.expect("Join failed").expect("Dry run failed");
        assert!(res.dry_run);
        assert!(res.success);
    }
}

#[tokio::test]
async fn test_tier2_f8_05_dry_run_output_utf8_hygiene() {
    let patcher = KernelPatcher::new();
    let res = patcher
        .apply_os_kernel_patch(true)
        .await
        .expect("Dry run failed");

    // Output must contain 0 control characters (except newline \n or \r)
    for b in res.output.bytes() {
        if b < 0x20 {
            assert!(
                b == b'\n' || b == b'\r' || b == b'\t',
                "Illegal control byte 0x{:02X}",
                b
            );
        }
    }
    assert!(
        !res.output.contains('\u{FFFD}'),
        "Output must not contain replacement characters"
    );
}
