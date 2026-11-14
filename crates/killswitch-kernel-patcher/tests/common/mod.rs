//! Shared test harness, authentic NVD API 2.0 JSON fixtures, ephemeral Tokio mock server,
//! and verification helper utilities for `killswitch-kernel-patcher`.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use killswitch_kernel_patcher::{HostKernelInfo, KernelVulnerability, OsFamily, ScanOptions};

// =============================================================================
// 1. Authentic NIST NVD API 2.0 JSON Fixtures
// =============================================================================

/// Empty valid NVD API 2.0 response with 0 CVE entries.
pub const FIXTURE_EMPTY_NVD_JSON: &str = r#"{
  "resultsPerPage": 0,
  "startIndex": 0,
  "totalResults": 0,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2026-11-13T21:00:00.000",
  "vulnerabilities": []
}"#;

/// Single CISA KEV vulnerability fixture (CVE-2024-1086: Linux netfilter use-after-free).
pub const FIXTURE_SINGLE_KEV_CVE_JSON: &str = r#"{
  "resultsPerPage": 1,
  "startIndex": 0,
  "totalResults": 1,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2026-11-13T21:00:00.000",
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2024-1086",
        "sourceIdentifier": "cve@mitre.org",
        "published": "2024-01-31T13:15:08.527",
        "lastModified": "2024-02-05T14:15:09.123",
        "vulnStatus": "Analyzed",
        "descriptions": [
          {
            "lang": "en",
            "value": "A use-after-free vulnerability in the Linux kernel netfilter nf_tables component allows local privilege escalation."
          }
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "attackVector": "LOCAL",
                "attackComplexity": "LOW",
                "privilegesRequired": "LOW",
                "userInteraction": "NONE",
                "scope": "UNCHANGED",
                "confidentialityImpact": "HIGH",
                "integrityImpact": "HIGH",
                "availabilityImpact": "HIGH",
                "baseScore": 7.8,
                "baseSeverity": "HIGH"
              },
              "exploitabilityScore": 1.8,
              "impactScore": 5.9
            }
          ]
        },
        "cisaExploitAdd": "2024-03-25",
        "cisaActionDue": "2024-04-15",
        "cisaRequiredAction": "Apply mitigations per vendor instructions or discontinue use of the product.",
        "cisaVulnerabilityName": "Linux Kernel Netfilter Use-After-Free Vulnerability"
      }
    }
  ]
}"#;

/// Single Windows CISA KEV vulnerability fixture (CVE-2024-21338: Windows Kernel EoP).
pub const FIXTURE_WINDOWS_KEV_CVE_JSON: &str = r#"{
  "resultsPerPage": 1,
  "startIndex": 0,
  "totalResults": 1,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2026-11-13T21:00:00.000",
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2024-21338",
        "sourceIdentifier": "secure@microsoft.com",
        "published": "2024-02-13T18:15:00.000",
        "lastModified": "2024-02-29T10:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [
          {
            "lang": "en",
            "value": "Windows Kernel Elevation of Privilege Vulnerability allowing an attacker with local access to gain SYSTEM privileges."
          }
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "attackVector": "LOCAL",
                "attackComplexity": "LOW",
                "privilegesRequired": "LOW",
                "userInteraction": "NONE",
                "scope": "UNCHANGED",
                "confidentialityImpact": "HIGH",
                "integrityImpact": "HIGH",
                "availabilityImpact": "HIGH",
                "baseScore": 7.8,
                "baseSeverity": "HIGH"
              },
              "exploitabilityScore": 1.8,
              "impactScore": 5.9
            }
          ]
        },
        "cisaExploitAdd": "2024-02-29",
        "cisaActionDue": "2024-03-21",
        "cisaRequiredAction": "Apply updates per vendor instructions.",
        "cisaVulnerabilityName": "Microsoft Windows Kernel Privilege Escalation Vulnerability"
      }
    }
  ]
}"#;

/// Single Non-KEV High-Severity vulnerability fixture (CVE-2024-9999, CVSS 9.8 Critical).
pub const FIXTURE_NON_KEV_CRITICAL_CVE_JSON: &str = r#"{
  "resultsPerPage": 1,
  "startIndex": 0,
  "totalResults": 1,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2026-11-13T21:00:00.000",
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2024-9999",
        "sourceIdentifier": "cve@mitre.org",
        "published": "2024-05-01T10:00:00.000",
        "lastModified": "2024-05-02T10:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [
          {
            "lang": "en",
            "value": "Unauthenticated remote memory corruption flaw."
          }
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "attackVector": "NETWORK",
                "attackComplexity": "LOW",
                "privilegesRequired": "NONE",
                "userInteraction": "NONE",
                "scope": "UNCHANGED",
                "confidentialityImpact": "HIGH",
                "integrityImpact": "HIGH",
                "availabilityImpact": "HIGH",
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL"
              },
              "exploitabilityScore": 3.9,
              "impactScore": 5.9
            }
          ]
        }
      }
    }
  ]
}"#;

/// Multi-CVE fixture containing 5 entries designed for KEV-first prioritization and CVSS sorting tests:
/// 1. CVE-2024-1086: KEV = true, CVSS = 7.8
/// 2. CVE-2024-9999: KEV = false, CVSS = 9.8 (High CVSS but non-KEV)
/// 3. CVE-2023-4567: KEV = true, CVSS = 5.3 (Lower CVSS but KEV)
/// 4. CVE-2022-1234: KEV = false, CVSS = 4.3 (Low CVSS non-KEV)
/// 5. CVE-2021-0001: KEV = false, CVSS = None (Missing metrics)
pub const FIXTURE_MULTI_CVE_RANKING_JSON: &str = r#"{
  "resultsPerPage": 5,
  "startIndex": 0,
  "totalResults": 5,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2026-11-13T21:00:00.000",
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2024-9999",
        "descriptions": [{"lang": "en", "value": "Critical remote code execution without KEV"}],
        "metrics": {
          "cvssMetricV31": [{
            "source": "nvd@nist.gov",
            "type": "Primary",
            "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL"}
          }]
        }
      }
    },
    {
      "cve": {
        "id": "CVE-2024-1086",
        "descriptions": [{"lang": "en", "value": "Linux netfilter local root"}],
        "metrics": {
          "cvssMetricV31": [{
            "source": "nvd@nist.gov",
            "type": "Primary",
            "cvssData": {"version": "3.1", "baseScore": 7.8, "baseSeverity": "HIGH"}
          }]
        },
        "cisaExploitAdd": "2024-03-25",
        "cisaActionDue": "2024-04-15",
        "cisaRequiredAction": "Apply updates.",
        "cisaVulnerabilityName": "Linux Kernel Netfilter Privilege Escalation"
      }
    },
    {
      "cve": {
        "id": "CVE-2023-4567",
        "descriptions": [{"lang": "en", "value": "Medium severity KEV vulnerability"}],
        "metrics": {
          "cvssMetricV31": [{
            "source": "nvd@nist.gov",
            "type": "Primary",
            "cvssData": {"version": "3.1", "baseScore": 5.3, "baseSeverity": "MEDIUM"}
          }]
        },
        "cisaExploitAdd": "2023-10-10",
        "cisaActionDue": "2023-11-01",
        "cisaRequiredAction": "Patch immediately.",
        "cisaVulnerabilityName": "Older Active Exploit"
      }
    },
    {
      "cve": {
        "id": "CVE-2022-1234",
        "descriptions": [{"lang": "en", "value": "Low severity non-KEV issue"}],
        "metrics": {
          "cvssMetricV31": [{
            "source": "nvd@nist.gov",
            "type": "Primary",
            "cvssData": {"version": "3.1", "baseScore": 4.3, "baseSeverity": "MEDIUM"}
          }]
        }
      }
    },
    {
      "cve": {
        "id": "CVE-2021-0001",
        "descriptions": [{"lang": "en", "value": "Unscored informational finding"}],
        "metrics": {}
      }
    }
  ]
}"#;

/// Fixture containing CISA KEV vulnerability with partial optional fields (cisaActionDue omitted).
pub const FIXTURE_PARTIAL_KEV_JSON: &str = r#"{
  "resultsPerPage": 1,
  "startIndex": 0,
  "totalResults": 1,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2024-02-29T12:00:00.000",
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2024-21338",
        "sourceIdentifier": "secure@microsoft.com",
        "published": "2024-02-13T18:15:58.200",
        "lastModified": "2024-02-29T21:15:47.300",
        "vulnStatus": "Modified",
        "cisaExploitAdd": "2024-02-29",
        "descriptions": [
          {
            "lang": "en",
            "value": "Windows Kernel Elevation of Privilege Vulnerability (appid.sys AppLocker driver previously exploited in the wild as a zero-day)."
          }
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "baseScore": 7.8,
                "baseSeverity": "HIGH"
              }
            }
          ]
        }
      }
    }
  ]
}"#;

/// Fixture containing both CVSS v3.1 Primary and CVSS v2.0 Secondary metrics.
pub const FIXTURE_MULTI_METRIC_JSON: &str = r#"{
  "resultsPerPage": 1,
  "startIndex": 0,
  "totalResults": 1,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2023-08-01T12:00:00.000",
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2023-38606",
        "sourceIdentifier": "product-security@apple.com",
        "published": "2023-07-24T21:15:10.500",
        "lastModified": "2023-08-01T15:15:00.000",
        "vulnStatus": "Analyzed",
        "cisaExploitAdd": "2023-07-25",
        "cisaActionDue": "2023-08-15",
        "cisaRequiredAction": "Apply mitigations per vendor instructions.",
        "descriptions": [
          {
            "lang": "en",
            "value": "An app may be able to modify sensitive kernel state. Apple is aware of a report that this issue may have been actively exploited."
          }
        ],
        "metrics": {
          "cvssMetricV31": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                "baseScore": 7.8,
                "baseSeverity": "HIGH"
              }
            }
          ],
          "cvssMetricV2": [
            {
              "source": "nvd@nist.gov",
              "type": "Secondary",
              "cvssData": {
                "version": "2.0",
                "vectorString": "AV:L/AC:M/Au:N/C:C/I:C/A:C",
                "baseScore": 6.9
              }
            }
          ]
        }
      }
    }
  ]
}"#;

/// NVD API 429 Rate Limit error response body.
pub const FIXTURE_RATE_LIMIT_429_BODY: &str = r#"{
  "message": "Request forbidden by administrative rules: Rate limit exceeded"
}"#;

/// Malformed JSON payload to test fail-closed deserialization error handling.
pub const FIXTURE_MALFORMED_JSON: &str =
    r#"{"resultsPerPage": 1, "vulnerabilities": [{"cve": {"id": "CVE-2024"#;

// =============================================================================
// 2. Ephemeral In-Memory Mock NVD Server (`MockNvdServer`)
// =============================================================================

pub trait IntoStatusCode {
    fn to_code(self) -> u16;
}

impl IntoStatusCode for u16 {
    fn to_code(self) -> u16 {
        self
    }
}

impl IntoStatusCode for reqwest::StatusCode {
    fn to_code(self) -> u16 {
        self.as_u16()
    }
}

/// Lightweight, in-process HTTP mock server running on an ephemeral OS-assigned port.
pub struct MockNvdServer {
    pub addr: SocketAddr,
    pub endpoint_url: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
    received_headers: Arc<Mutex<Vec<(String, String)>>>,
    request_count: Arc<Mutex<usize>>,
}

impl MockNvdServer {
    /// Launches an ephemeral mock server returning 200 OK with the given JSON fixture.
    pub async fn start(fixture_json: &'static str) -> Self {
        Self::start_with_config(fixture_json, 200, 0).await
    }

    /// Launches an ephemeral mock server returning a custom HTTP status code and body.
    pub async fn start_with_status<S: IntoStatusCode>(status: S, body: &'static str) -> Self {
        Self::start_with_config(body, status.to_code(), 0).await
    }

    /// Launches an ephemeral mock server introducing an artificial delay to test timeouts.
    pub async fn start_with_delay(fixture_json: &'static str, delay_ms: u64) -> Self {
        Self::start_with_config(fixture_json, 200, delay_ms).await
    }

    async fn start_with_config(body: &'static str, status_code: u16, delay_ms: u64) -> Self {
        let received_headers = Arc::new(Mutex::new(Vec::new()));
        let request_count = Arc::new(Mutex::new(0));

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind ephemeral TCP port on 127.0.0.1");
        let addr = listener.local_addr().expect("Failed to get local address");
        let endpoint_url = format!("http://{}/rest/json/cves/2.0", addr);

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        let headers_clone = Arc::clone(&received_headers);
        let count_clone = Arc::clone(&request_count);
        let body_str = body.to_string();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((mut stream, _)) => {
                                let h_clone = Arc::clone(&headers_clone);
                                let c_clone = Arc::clone(&count_clone);
                                let b_clone = body_str.clone();

                                tokio::spawn(async move {
                                    let mut buf = [0u8; 4096];
                                    let mut received = Vec::new();

                                    // Read HTTP request until headers are complete (\r\n\r\n) or connection closes
                                    while let Ok(n) = stream.read(&mut buf).await {
                                        if n == 0 {
                                            break;
                                        }
                                        received.extend_from_slice(&buf[..n]);
                                        if received.windows(4).any(|w| w == b"\r\n\r\n") {
                                            break;
                                        }
                                    }

                                    // Parse request headers
                                    if !received.is_empty() {
                                        *c_clone.lock().unwrap() += 1;
                                        let req_str = String::from_utf8_lossy(&received);
                                        for line in req_str.lines() {
                                            if let Some((k, v)) = line.split_once(':') {
                                                h_clone.lock().unwrap().push((
                                                    k.trim().to_string(),
                                                    v.trim().to_string(),
                                                ));
                                            }
                                        }
                                    }

                                    if delay_ms > 0 {
                                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                    }

                                    let reason = match status_code {
                                        200 => "OK",
                                        400 => "Bad Request",
                                        403 => "Forbidden",
                                        404 => "Not Found",
                                        429 => "Too Many Requests",
                                        500 => "Internal Server Error",
                                        503 => "Service Unavailable",
                                        _ => "Response",
                                    };

                                    let response = format!(
                                        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                        status_code, reason, b_clone.len(), b_clone
                                    );

                                    let _ = stream.write_all(response.as_bytes()).await;
                                    let _ = stream.flush().await;
                                });
                            }
                            Err(_) => {
                                break;
                            }
                        }
                    }
                }
            }
        });

        Self {
            addr,
            endpoint_url,
            shutdown_tx: Some(shutdown_tx),
            received_headers,
            request_count,
        }
    }

    /// Returns the last received `apiKey` header value, if any was transmitted.
    pub fn last_api_key(&self) -> Option<String> {
        self.received_headers
            .lock()
            .unwrap()
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("apiKey"))
            .map(|(_, v)| v.clone())
    }

    /// Checks if a specific header was sent by the client.
    pub fn has_header(&self, header_name: &str) -> bool {
        self.received_headers
            .lock()
            .unwrap()
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case(header_name))
    }

    /// Returns the total number of HTTP requests received by this mock server instance.
    pub fn total_requests(&self) -> usize {
        *self.request_count.lock().unwrap()
    }
}

impl Drop for MockNvdServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

// =============================================================================
// 3. Test Fixture & Verification Helper Utilities
// =============================================================================

/// Generates a synthetic but structurally authentic `HostKernelInfo` for testing.
pub fn sample_host_kernel(os: OsFamily) -> HostKernelInfo {
    match os {
        OsFamily::Linux => HostKernelInfo {
            os_family: OsFamily::Linux,
            kernel_release: "6.8.0-40-generic".to_string(),
            os_version: "Ubuntu 24.04 LTS".to_string(),
            cpe23: "cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*".to_string(),
            architecture: "x86_64".to_string(),
        },
        OsFamily::Windows => HostKernelInfo {
            os_family: OsFamily::Windows,
            kernel_release: "10.0.26100".to_string(),
            os_version: "Windows 11 Pro 24H2".to_string(),
            cpe23: "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*".to_string(),
            architecture: "x86_64".to_string(),
        },
        OsFamily::MacOS => HostKernelInfo {
            os_family: OsFamily::MacOS,
            kernel_release: "23.5.0".to_string(),
            os_version: "macOS 14.5".to_string(),
            cpe23: "cpe:2.3:o:apple:macos:14.5:*:*:*:*:*:*:*".to_string(),
            architecture: "aarch64".to_string(),
        },
        OsFamily::Unknown(ref name) => HostKernelInfo {
            os_family: os.clone(),
            kernel_release: "0.0.0".to_string(),
            os_version: format!("Generic {}", name),
            cpe23: "cpe:2.3:o:unknown:unknown:0.0.0:*:*:*:*:*:*:*".to_string(),
            architecture: "unknown".to_string(),
        },
    }
}

/// Creates default `ScanOptions` configured for test execution against a custom endpoint.
pub fn test_scan_options(
    cpe: Option<&str>,
    min_cvss: Option<f32>,
    kev_only: bool,
    api_key: Option<&str>,
) -> ScanOptions {
    ScanOptions {
        cpe: cpe.map(|s| s.to_string()),
        min_cvss_score: min_cvss,
        kev_only,
        api_key: api_key.map(|s| s.to_string()),
        timeout_secs: 5,
    }
}

/// Asserts that vulnerabilities are sorted strictly according to the KillSwitch specification:
/// 1. All CISA KEV entries (`is_cisa_kev == true`) appear before any non-KEV entry.
/// 2. Within the KEV subset, CVSS scores are monotonically non-increasing.
/// 3. Within the non-KEV subset, CVSS scores are monotonically non-increasing.
pub fn assert_vulnerability_ranking(vulns: &[KernelVulnerability]) {
    let mut seen_non_kev = false;
    let mut last_kev_score: Option<f32> = None;
    let mut last_non_kev_score: Option<f32> = None;

    for v in vulns {
        if v.is_cisa_kev {
            assert!(
                !seen_non_kev,
                "Ranking invariant violated: KEV entry '{}' appeared after non-KEV entries",
                v.cve_id
            );
            if let (Some(prev), Some(curr)) = (last_kev_score, v.cvss_v31_score) {
                assert!(
                    prev >= curr,
                    "KEV CVSS descending order violated: {} had score {} but previous was {}",
                    v.cve_id,
                    curr,
                    prev
                );
            }
            last_kev_score = v.cvss_v31_score;
        } else {
            seen_non_kev = true;
            if let (Some(prev), Some(curr)) = (last_non_kev_score, v.cvss_v31_score) {
                assert!(
                    prev >= curr,
                    "Non-KEV CVSS descending order violated: {} had score {} but previous was {}",
                    v.cve_id,
                    curr,
                    prev
                );
            }
            last_non_kev_score = v.cvss_v31_score;
        }
    }
}

/// Verifies that a generated string matches standard CPE 2.3 syntax.
pub fn assert_valid_cpe23(cpe: &str) {
    assert!(
        cpe.starts_with("cpe:2.3:o:"),
        "CPE 2.3 must start with 'cpe:2.3:o:': got '{}'",
        cpe
    );
    let parts: Vec<&str> = cpe.split(':').collect();
    assert_eq!(
        parts.len(),
        13,
        "CPE 2.3 formatted string must have exactly 13 colon-separated fields: got {} in '{}'",
        parts.len(),
        cpe
    );
}

/// Fast non-panicking connectivity probe to verify if NIST NVD is reachable.
pub async fn is_live_nvd_reachable() -> bool {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(2000))
        .build();

    match client {
        Ok(c) => {
            match c
                .get("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1")
                .send()
                .await
            {
                Ok(resp) => resp.status().is_success() || resp.status().as_u16() == 429,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}
