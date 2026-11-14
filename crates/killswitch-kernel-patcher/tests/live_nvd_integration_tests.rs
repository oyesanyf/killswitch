//! Live NVD API 2.0 network integration test suite.
//! Connects to live NIST REST API with network reachability checks, rate limit tolerance,
//! and secret hygiene enforcement (reading NVD_API_KEY strictly from runtime environment).

mod common;
use common::*;
use killswitch_kernel_patcher::{KernelPatcher, PatcherError};

#[tokio::test]
async fn test_live_nvd_reachability_probe() {
    let reachable = is_live_nvd_reachable().await;
    println!("NIST NVD live reachability status: {}", reachable);
}

#[tokio::test]
async fn test_live_nvd_api_query_with_or_without_key() {
    if !is_live_nvd_reachable().await {
        println!("Live NVD endpoint unreachable or rate limited; skipping live network test");
        return;
    }

    let patcher = KernelPatcher::new();

    // Mandatory Secret Hygiene: Read strictly from runtime environment variable
    let api_key = std::env::var("NVD_API_KEY").ok();

    let query_cpe = "cpe:2.3:o:linux:linux_kernel:6.1.0:*:*:*:*:*:*:*";
    let options = test_scan_options(Some(query_cpe), None, false, api_key.as_deref());

    match patcher.scan_kernel_vulnerabilities(&options).await {
        Ok(vulns) => {
            println!(
                "Live NVD 2.0 query returned {} vulnerabilities",
                vulns.len()
            );
            if !vulns.is_empty() {
                assert_vulnerability_ranking(&vulns);
            }
        }
        Err(PatcherError::RateLimited) => {
            println!("NVD returned 429 Too Many Requests; tolerated gracefully");
        }
        Err(PatcherError::Network(e)) => {
            println!(
                "Network transport error contacting NIST: {}; tolerated gracefully",
                e
            );
        }
        Err(other) => {
            panic!("Unexpected error querying live NVD API: {:?}", other);
        }
    }
}

#[tokio::test]
async fn test_live_nvd_ranking_validation() {
    if !is_live_nvd_reachable().await {
        println!("Live NVD endpoint unreachable; skipping ranking validation");
        return;
    }

    let patcher = KernelPatcher::new();
    let api_key = std::env::var("NVD_API_KEY").ok();

    // Scan a known older kernel to get a rich set of CVEs
    let query_cpe = "cpe:2.3:o:linux:linux_kernel:5.10.0:*:*:*:*:*:*:*";
    let options = test_scan_options(Some(query_cpe), None, false, api_key.as_deref());

    match patcher.scan_kernel_vulnerabilities(&options).await {
        Ok(vulns) => {
            if !vulns.is_empty() {
                assert_vulnerability_ranking(&vulns);
            }
        }
        Err(PatcherError::RateLimited) | Err(PatcherError::Network(_)) => {
            // Tolerated gracefully in automated runs
        }
        Err(e) => {
            panic!("Unexpected error in live scan: {:?}", e);
        }
    }
}
