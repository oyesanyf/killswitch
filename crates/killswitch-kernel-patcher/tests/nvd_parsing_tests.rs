//! Dedicated NVD API 2.0 JSON parsing, metric extraction, and KEV prioritization test suite.

mod common;
use common::*;
use killswitch_kernel_patcher::{KernelPatcher, PatcherError};

#[tokio::test]
async fn test_nvd_parsing_single_kev_fields() {
    let server = MockNvdServer::start(FIXTURE_SINGLE_KEV_CVE_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Parsing failed");

    assert_eq!(vulns.len(), 1);
    let v = &vulns[0];
    assert_eq!(v.cve_id, "CVE-2024-1086");
    assert!(v.is_cisa_kev);
    assert_eq!(v.cvss_v31_score, Some(7.8));
    assert_eq!(v.cvss_v31_severity.as_deref(), Some("HIGH"));
    assert_eq!(v.cisa_exploit_add.as_deref(), Some("2024-03-25"));
    assert_eq!(v.cisa_action_due.as_deref(), Some("2024-04-15"));
    assert!(v.cisa_required_action.is_some());
    assert!(v.cisa_vulnerability_name.is_some());
    assert!(v.description.contains("netfilter"));
}

#[tokio::test]
async fn test_nvd_parsing_windows_kev_fields() {
    let server = MockNvdServer::start(FIXTURE_WINDOWS_KEV_CVE_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Parsing failed");

    assert_eq!(vulns.len(), 1);
    let v = &vulns[0];
    assert_eq!(v.cve_id, "CVE-2024-21338");
    assert!(v.is_cisa_kev);
    assert_eq!(v.cvss_v31_score, Some(7.8));
    assert_eq!(v.cisa_exploit_add.as_deref(), Some("2024-02-29"));
    assert!(v
        .description
        .contains("Windows Kernel Elevation of Privilege"));
}

#[tokio::test]
async fn test_nvd_parsing_non_kev_critical() {
    let server = MockNvdServer::start(FIXTURE_NON_KEV_CRITICAL_CVE_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Parsing failed");

    assert_eq!(vulns.len(), 1);
    let v = &vulns[0];
    assert_eq!(v.cve_id, "CVE-2024-9999");
    assert!(!v.is_cisa_kev);
    assert_eq!(v.cvss_v31_score, Some(9.8));
    assert_eq!(v.cvss_v31_severity.as_deref(), Some("CRITICAL"));
    assert_eq!(v.cisa_exploit_add, None);
}

#[tokio::test]
async fn test_nvd_parsing_multi_cve_sorting() {
    let server = MockNvdServer::start(FIXTURE_MULTI_CVE_RANKING_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Parsing failed");

    assert_eq!(vulns.len(), 5);
    assert_vulnerability_ranking(&vulns);

    // Explicit ordering assertion
    assert_eq!(vulns[0].cve_id, "CVE-2024-1086");
    assert_eq!(vulns[1].cve_id, "CVE-2023-4567");
    assert_eq!(vulns[2].cve_id, "CVE-2024-9999");
    assert_eq!(vulns[3].cve_id, "CVE-2022-1234");
    assert_eq!(vulns[4].cve_id, "CVE-2021-0001");
}

#[tokio::test]
async fn test_nvd_parsing_partial_kev_fields() {
    let server = MockNvdServer::start(FIXTURE_PARTIAL_KEV_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Parsing failed");

    assert_eq!(vulns.len(), 1);
    let v = &vulns[0];
    assert!(v.is_cisa_kev);
    assert_eq!(v.cisa_action_due, None);
    assert_eq!(v.cisa_required_action, None);
}

#[tokio::test]
async fn test_nvd_parsing_multi_metric_precedence() {
    let server = MockNvdServer::start(FIXTURE_MULTI_METRIC_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Parsing failed");

    assert_eq!(vulns.len(), 1);
    let v = &vulns[0];
    assert_eq!(
        v.cvss_v31_score,
        Some(7.8),
        "Must select CVSS v3.1 score over v2.0 score"
    );
}

#[tokio::test]
async fn test_nvd_parsing_empty_results() {
    let server = MockNvdServer::start(FIXTURE_EMPTY_NVD_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let vulns = patcher
        .scan_kernel_vulnerabilities(&opts)
        .await
        .expect("Parsing failed");

    assert!(vulns.is_empty());
}

#[tokio::test]
async fn test_nvd_parsing_malformed_json_fails_closed() {
    let server = MockNvdServer::start(FIXTURE_MALFORMED_JSON).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let res = patcher.scan_kernel_vulnerabilities(&opts).await;

    assert!(matches!(res, Err(PatcherError::Serialization(_))));
}

#[tokio::test]
async fn test_nvd_parsing_rate_limit_429() {
    let server = MockNvdServer::start_with_status(429, FIXTURE_RATE_LIMIT_429_BODY).await;
    let patcher = KernelPatcher::with_base_url(&server.endpoint_url);

    let opts = test_scan_options(None, None, false, None);
    let res = patcher.scan_kernel_vulnerabilities(&opts).await;

    assert!(matches!(res, Err(PatcherError::RateLimited)));
}
