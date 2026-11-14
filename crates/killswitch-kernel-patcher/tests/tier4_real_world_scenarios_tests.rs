//! Tier 4: Real-World Scenarios Test Suite for `killswitch-kernel-patcher`.
//! Covers Scenarios S1 through S5 exercising end-to-end operational flows.

mod common;
use common::*;
use killswitch_kernel_patcher::{
    is_elevated, HostKernelInfo, KernelPatcher, OsFamily, PatcherError,
};

#[test]
fn test_tier4_s1_active_host_kernel_discovery() {
    let info = HostKernelInfo::detect_host_kernel().expect("Host kernel detection failed");

    // Platform validation
    #[cfg(target_os = "windows")]
    assert_eq!(info.os_family, OsFamily::Windows);
    #[cfg(target_os = "linux")]
    assert_eq!(info.os_family, OsFamily::Linux);
    #[cfg(target_os = "macos")]
    assert_eq!(info.os_family, OsFamily::MacOS);

    // Release and architecture
    assert!(
        !info.kernel_release.is_empty(),
        "Kernel release cannot be empty"
    );
    assert!(
        !info.architecture.is_empty(),
        "Architecture cannot be empty"
    );
    assert!(
        ["x86_64", "aarch64", "x86", "arm"].contains(&info.architecture.as_str()),
        "Architecture should be canonical, got {}",
        info.architecture
    );

    // CPE 2.3 verification
    let cpe = info.to_cpe23();
    assert_valid_cpe23(&cpe);
    assert_eq!(info.cpe23, cpe);
}

#[tokio::test]
async fn test_tier4_s2_offline_kev_pipeline() {
    let server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let options = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&options)
        .await
        .expect("Offline scan failed");

    assert_eq!(vulns.len(), 5, "Fixture contains exactly 5 vulnerabilities");

    // Invariant: KEV entries must strictly precede non-KEV entries
    assert_vulnerability_ranking(&vulns);

    // Verifying specific positions
    assert_eq!(vulns[0].cve_id, "CVE-2024-1086"); // KEV, CVSS 7.8
    assert!(vulns[0].is_cisa_kev);
    assert_eq!(vulns[1].cve_id, "CVE-2023-4567"); // KEV, CVSS 5.3
    assert!(vulns[1].is_cisa_kev);
    assert_eq!(vulns[2].cve_id, "CVE-2024-9999"); // Non-KEV, CVSS 9.8 (Subordinated to KEV)
    assert!(!vulns[2].is_cisa_kev);
    assert_eq!(vulns[3].cve_id, "CVE-2022-1234"); // Non-KEV, CVSS 4.3
    assert_eq!(vulns[4].cve_id, "CVE-2021-0001"); // Non-KEV, unscored
}

#[tokio::test]
async fn test_tier4_s3_dry_run_remediation_workflow() {
    let server = MockNvdServer::start(FIXTURE_SINGLE_KEV_CVE_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    // Step 1: Detect host kernel
    let host_info = HostKernelInfo::detect_host_kernel().expect("Host detection failed");
    let cpe = host_info.to_cpe23();

    // Step 2: Scan vulnerabilities using detected CPE
    let scan_opts = test_scan_options(Some(&cpe), None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&scan_opts)
        .await
        .expect("Scan failed");
    assert!(!vulns.is_empty());

    // Step 3: Trigger safe dry-run orchestration
    let plan = patcher
        .apply_os_kernel_patch(true)
        .await
        .expect("Dry run failed");

    // Invariant: Zero system mutation
    assert!(plan.dry_run);
    assert!(plan.success);
    assert!(!plan.command.is_empty());
    assert!(!plan.args.is_empty());
    assert!(plan.output.contains("[DRY-RUN]"));

    #[cfg(target_os = "windows")]
    assert_eq!(plan.command, "UsoClient.exe");
    #[cfg(target_os = "macos")]
    assert_eq!(plan.command, "softwareupdate");
}

#[tokio::test]
async fn test_tier4_s4_non_elevated_privilege_guard() {
    let patcher = KernelPatcher::new();

    if !is_elevated() {
        // Must return InsufficientPrivileges
        let result = patcher.apply_os_kernel_patch(false).await;
        match result {
            Err(PatcherError::InsufficientPrivileges) => {
                // Expected fail-closed behavior
            }
            other => panic!("Expected InsufficientPrivileges, got {:?}", other),
        }
    } else {
        println!("Test runner is running with elevated privileges; skipping non-elevated assert");
    }
}

#[tokio::test]
async fn test_tier4_s5_live_nvd_integration_query() {
    if !is_live_nvd_reachable().await {
        println!("NIST NVD 2.0 API is unreachable or rate limited; skipping live network test");
        return;
    }

    let patcher = KernelPatcher::new();
    let api_key = std::env::var("NVD_API_KEY").ok();

    // Query for a widely known Linux kernel CPE
    let query_cpe = "cpe:2.3:o:linux:linux_kernel:5.15.0:*:*:*:*:*:*:*";
    let options = test_scan_options(Some(query_cpe), None, false, api_key.as_deref());

    let res = patcher.scan_kernel_vulnerabilities(&options).await;
    match res {
        Ok(vulns) => {
            println!(
                "Successfully queried live NIST NVD 2.0! Received {} vulnerabilities",
                vulns.len()
            );
            if !vulns.is_empty() {
                assert_vulnerability_ranking(&vulns);
            }
        }
        Err(PatcherError::RateLimited) => {
            println!("NIST NVD returned 429 Rate Limited; gracefully tolerated");
        }
        Err(PatcherError::Network(e)) => {
            println!(
                "Transient network error contacting NIST: {}; skipping gracefully",
                e
            );
        }
        Err(other) => {
            panic!("Unexpected error from live NVD endpoint: {:?}", other);
        }
    }
}
