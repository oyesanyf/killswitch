//! Tier 3: Pairwise Combinatorial Feature Interactions Test Suite for `killswitch-kernel-patcher`.
//! Covers 12 cross-feature interaction combinations across Discovery, Auth, Scanning, Scoring,
//! Privilege Evaluation, and Patch Orchestration.

mod common;
use common::*;
use killswitch_kernel_patcher::{is_elevated, HostKernelInfo, KernelPatcher, PatcherError};

#[tokio::test]
async fn test_tier3_01_kev_prioritization_with_dry_run_dispatch() {
    let server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let options = test_scan_options(
        Some("cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*"),
        None,
        false,
        None,
    );
    let vulns = patcher
        .scan_kernel_vulnerabilities(&options)
        .await
        .expect("Scan failed");

    // Invariant 1: Top vulnerability MUST be CISA KEV even if a non-KEV has higher CVSS
    assert!(vulns[0].is_cisa_kev, "Top finding must be KEV");
    assert_eq!(vulns[0].cve_id, "CVE-2024-1086");

    // Invariant 2: Trigger dry-run patch planning based on discovered KEV threat
    let patch_res = patcher
        .apply_os_kernel_patch(true)
        .await
        .expect("Dry run patch planning failed");
    assert!(patch_res.dry_run);
    assert!(patch_res.success);
    assert!(!patch_res.command.is_empty());
    assert!(!patch_res.args.is_empty());
    assert!(patch_res.output.contains("[DRY-RUN]"));
}

#[tokio::test]
async fn test_tier3_02_cvss_threshold_filter_and_dispatch_gate() {
    let server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    // Scenario A: Filter min_cvss_score >= 8.0 (Only CVE-2024-9999 with 9.8 should survive)
    let options = test_scan_options(None, Some(8.0), false, None);
    let filtered_vulns = patcher
        .scan_kernel_vulnerabilities(&options)
        .await
        .expect("Scan failed");
    for v in &filtered_vulns {
        assert!(v.cvss_v31_score.unwrap_or(0.0) >= 8.0);
    }
    assert_eq!(filtered_vulns.len(), 1);
    assert_eq!(filtered_vulns[0].cve_id, "CVE-2024-9999");

    // Scenario B: Filter min_cvss_score >= 9.9 (Zero should survive)
    let empty_options = test_scan_options(None, Some(9.9), false, None);
    let empty_res = patcher
        .scan_kernel_vulnerabilities(&empty_options)
        .await
        .expect("Scan failed");
    assert_eq!(empty_res.len(), 0);
}

#[tokio::test]
async fn test_tier3_03_nvd_api_key_auth_with_kev_only_filter() {
    let server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let test_key = "test_nvd_api_key_secret_abc123";
    let options = test_scan_options(None, None, true, Some(test_key));

    let vulns = patcher
        .scan_kernel_vulnerabilities(&options)
        .await
        .expect("Scan failed");

    // Verify header arrived at mock server
    assert_eq!(server.last_api_key(), Some(test_key.to_string()));

    // Verify kev_only filtering removed all non-KEV items
    assert!(!vulns.is_empty());
    for v in &vulns {
        assert!(
            v.is_cisa_kev,
            "All returned findings must be CISA KEV entries"
        );
    }
    assert!(!vulns.iter().any(|v| v.cve_id == "CVE-2024-9999"));
}

#[tokio::test]
async fn test_tier3_04_host_discovery_cpe_to_nvd_query_dispatch() {
    let server = MockNvdServer::start(FIXTURE_EMPTY_NVD_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let host_info = HostKernelInfo::detect_host_kernel().expect("Host kernel detection failed");
    let cpe = host_info.to_cpe23();
    assert_valid_cpe23(&cpe);

    // Call scan with default host CPE
    let options = test_scan_options(Some(&cpe), None, false, None);
    let _ = patcher
        .scan_kernel_vulnerabilities(&options)
        .await
        .expect("Scan failed");

    assert_eq!(server.total_requests(), 1);
}

#[tokio::test]
async fn test_tier3_05_privilege_boundary_live_vs_dry_run_interaction() {
    let patcher = KernelPatcher::new();

    if !is_elevated() {
        // Invariant: Non-elevated live patch MUST fail closed with InsufficientPrivileges
        let live_res = patcher.apply_os_kernel_patch(false).await;
        assert!(
            matches!(live_res, Err(PatcherError::InsufficientPrivileges)),
            "Expected InsufficientPrivileges under non-elevated context, got {:?}",
            live_res
        );
    }

    // Invariant: Dry run MUST succeed regardless of privilege state
    let dry_res = patcher
        .apply_os_kernel_patch(true)
        .await
        .expect("Dry run must always succeed");
    assert!(dry_res.dry_run);
    assert!(dry_res.success);
}

#[tokio::test]
async fn test_tier3_06_rate_limited_response_without_api_key() {
    let server = MockNvdServer::start_with_status(429, FIXTURE_RATE_LIMIT_429_BODY).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let options = test_scan_options(None, None, false, None);
    let res = patcher.scan_kernel_vulnerabilities(&options).await;

    assert!(matches!(res, Err(PatcherError::RateLimited)));
}

#[tokio::test]
async fn test_tier3_07_empty_vulnerability_set_patch_dispatch() {
    let server = MockNvdServer::start(FIXTURE_EMPTY_NVD_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let options = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&options)
        .await
        .expect("Scan failed");
    assert!(vulns.is_empty());

    // When 0 vulnerabilities exist, verify patch dry-run can still be audited cleanly
    let dry_res = patcher
        .apply_os_kernel_patch(true)
        .await
        .expect("Dry run succeeded");
    assert!(dry_res.dry_run);
}

#[tokio::test]
async fn test_tier3_08_custom_cpe_override_with_cvss_threshold() {
    let server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let custom_cpe = "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348:*:*:*:*:*:*:*";
    let options = test_scan_options(Some(custom_cpe), Some(7.0), false, None);

    let vulns = patcher
        .scan_kernel_vulnerabilities(&options)
        .await
        .expect("Scan failed");
    for v in &vulns {
        assert!(v.cvss_v31_score.unwrap_or(0.0) >= 7.0);
    }
}

#[tokio::test]
async fn test_tier3_09_multi_metric_kev_sorting_tiebreak() {
    let server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let options = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&options)
        .await
        .expect("Scan failed");

    // Invariant: CVSS ranking order
    assert_vulnerability_ranking(&vulns);
}

#[tokio::test]
async fn test_tier3_10_linux_subsystem_livepatch_fallback_dry_run() {
    let patcher = KernelPatcher::new();
    let res = patcher
        .apply_os_kernel_patch(true)
        .await
        .expect("Dry run planning failed");

    #[cfg(target_os = "linux")]
    {
        assert!(["canonical-livepatch", "apt-get", "dnf"].contains(&res.os_subsystem.as_str()));
    }
    #[cfg(target_os = "windows")]
    {
        assert_eq!(res.os_subsystem, "UsoClient");
        assert_eq!(res.command, "UsoClient.exe");
    }
    #[cfg(target_os = "macos")]
    {
        assert_eq!(res.os_subsystem, "softwareupdate");
        assert_eq!(res.command, "softwareupdate");
    }
}

#[tokio::test]
async fn test_tier3_11_malformed_nvd_payload_safeguard_patch_pipeline() {
    let server = MockNvdServer::start(FIXTURE_MALFORMED_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let options = test_scan_options(None, None, false, None);
    let res = patcher.scan_kernel_vulnerabilities(&options).await;

    assert!(matches!(res, Err(PatcherError::Serialization(_))));
}

#[tokio::test]
async fn test_tier3_12_concurrent_scan_and_dry_run_stress() {
    use std::sync::Arc;
    let server = Arc::new(MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await);
    let patcher = Arc::new(KernelPatcher::with_base_url(&server.endpoint_url));

    let mut set = tokio::task::JoinSet::new();

    for _ in 0..20 {
        let p = Arc::clone(&patcher);
        set.spawn(async move {
            let options = test_scan_options(None, None, false, None);
            let vulns = p.scan_kernel_vulnerabilities(&options).await.unwrap();
            let dry = p.apply_os_kernel_patch(true).await.unwrap();
            (vulns.len(), dry.dry_run)
        });
    }

    let mut completed = 0;
    while let Some(res) = set.join_next().await {
        let (v_len, dry_run) = res.expect("Task panicked");
        assert_eq!(v_len, 5);
        assert!(dry_run);
        completed += 1;
    }

    assert_eq!(completed, 20);
    assert_eq!(server.total_requests(), 20);
}
