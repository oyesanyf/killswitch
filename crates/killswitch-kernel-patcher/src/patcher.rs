//! NVD API 2.0 vulnerability scanner and OS-native patch orchestrator.

use serde_json::Value;
use std::time::Duration;

use crate::error::PatcherError;
use crate::privilege::is_elevated;
use crate::types::{HostKernelInfo, KernelVulnerability, PatchExecutionResult, ScanOptions};

/// Orchestrates OS kernel vulnerability scanning against NVD API 2.0 and native patch execution.
#[derive(Debug, Clone)]
pub struct KernelPatcher {
    base_url: String,
    client: reqwest::Client,
}

impl Default for KernelPatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelPatcher {
    /// Constructs a patcher pointing to the official NIST NVD API 2.0 endpoint.
    #[must_use]
    pub fn new() -> Self {
        Self::with_base_url("https://services.nvd.nist.gov/rest/json/cves/2.0")
    }

    /// Constructs a patcher pointing to a custom endpoint URL (useful for testing and mirrors).
    #[must_use]
    pub fn with_base_url(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Queries NVD API 2.0 for vulnerabilities matching the target or detected kernel CPE,
    /// extracting CVSS v3.1 metrics and CISA KEV metadata, and ranking findings KEV-first.
    pub async fn scan_kernel_vulnerabilities(
        &self,
        options: &ScanOptions,
    ) -> Result<Vec<KernelVulnerability>, PatcherError> {
        let target_cpe = match &options.cpe {
            Some(c) => c.clone(),
            None => HostKernelInfo::detect_host_kernel()?.cpe23,
        };

        let separator = if self.base_url.contains('?') {
            '&'
        } else {
            '?'
        };
        let url = format!("{}{}cpeName={}", self.base_url, separator, target_cpe);

        let mut req = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(options.timeout_secs));

        // API Key resolution: options.api_key takes precedence, then runtime env NVD_API_KEY.
        // Invariant: Never passed via CLI arguments to prevent leaking into OS process tables.
        let resolved_api_key = options
            .api_key
            .clone()
            .or_else(|| std::env::var("NVD_API_KEY").ok());

        if let Some(key) = resolved_api_key {
            req = req.header("apiKey", key);
        }

        let resp = req.send().await.map_err(PatcherError::Network)?;

        if resp.status().as_u16() == 429 {
            return Err(PatcherError::RateLimited);
        }

        if !resp.status().is_success() {
            return Err(PatcherError::NvdApiError(format!(
                "NVD API returned HTTP error: {}",
                resp.status()
            )));
        }

        let body_text = resp.text().await.map_err(PatcherError::Network)?;
        let parsed: Value =
            serde_json::from_str(&body_text).map_err(PatcherError::Serialization)?;

        let mut vulnerabilities = Vec::new();

        if let Some(vuln_items) = parsed.get("vulnerabilities").and_then(|v| v.as_array()) {
            for item in vuln_items {
                let Some(cve) = item.get("cve") else { continue };
                let Some(id) = cve.get("id").and_then(|i| i.as_str()) else {
                    continue;
                };

                // Description: English description preferred
                let mut description = String::new();
                if let Some(desc_array) = cve.get("descriptions").and_then(|d| d.as_array()) {
                    for d in desc_array {
                        if d.get("lang").and_then(|l| l.as_str()) == Some("en") {
                            if let Some(v) = d.get("value").and_then(|s| s.as_str()) {
                                description = v.to_string();
                                break;
                            }
                        }
                    }
                    if description.is_empty() {
                        if let Some(first) = desc_array
                            .first()
                            .and_then(|d| d.get("value"))
                            .and_then(|s| s.as_str())
                        {
                            description = first.to_string();
                        }
                    }
                }

                // CVSS v3.1 Metrics
                let mut cvss_score: Option<f32> = None;
                let mut cvss_severity: Option<String> = None;

                if let Some(v31_array) = cve
                    .get("metrics")
                    .and_then(|m| m.get("cvssMetricV31"))
                    .and_then(|a| a.as_array())
                {
                    if let Some(first_v31) = v31_array.first() {
                        if let Some(data) = first_v31.get("cvssData") {
                            cvss_score = data
                                .get("baseScore")
                                .and_then(|s| s.as_f64())
                                .map(|f| f as f32);
                            cvss_severity = data
                                .get("baseSeverity")
                                .and_then(|s| s.as_str())
                                .map(|s| s.to_string());
                        }
                    }
                }

                // CISA KEV Fields
                let cisa_exploit_add = cve
                    .get("cisaExploitAdd")
                    .and_then(|s| s.as_str())
                    .map(ToString::to_string);
                let cisa_action_due = cve
                    .get("cisaActionDue")
                    .and_then(|s| s.as_str())
                    .map(ToString::to_string);
                let cisa_required_action = cve
                    .get("cisaRequiredAction")
                    .and_then(|s| s.as_str())
                    .map(ToString::to_string);
                let cisa_vulnerability_name = cve
                    .get("cisaVulnerabilityName")
                    .and_then(|s| s.as_str())
                    .map(ToString::to_string);

                let is_cisa_kev = cisa_exploit_add.is_some()
                    || cisa_action_due.is_some()
                    || cisa_required_action.is_some()
                    || cisa_vulnerability_name.is_some();

                // Threshold & KEV-only filters
                if options.kev_only && !is_cisa_kev {
                    continue;
                }

                if let Some(min_score) = options.min_cvss_score {
                    let score = cvss_score.unwrap_or(0.0);
                    if score < min_score {
                        continue;
                    }
                }

                vulnerabilities.push(KernelVulnerability {
                    cve_id: id.to_string(),
                    description,
                    cvss_v31_score: cvss_score,
                    cvss_v31_severity: cvss_severity,
                    is_cisa_kev,
                    cisa_exploit_add,
                    cisa_action_due,
                    cisa_required_action,
                    cisa_vulnerability_name,
                });
            }
        }

        // Rank findings: CISA KEV entries first, descending by CVSS v3.1 base score
        vulnerabilities.sort_by(|a, b| match (a.is_cisa_kev, b.is_cisa_kev) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => {
                let sa = a.cvss_v31_score.unwrap_or(-1.0);
                let sb = b.cvss_v31_score.unwrap_or(-1.0);
                sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal)
            }
        });

        Ok(vulnerabilities)
    }

    /// Executes or dry-runs the OS-native kernel patch workflow.
    ///
    /// Non-dry-run operations require elevated privileges and will immediately fail closed
    /// with `PatcherError::InsufficientPrivileges` if not running as root/Administrator.
    pub async fn apply_os_kernel_patch(
        &self,
        dry_run: bool,
    ) -> Result<PatchExecutionResult, PatcherError> {
        if !dry_run && !is_elevated() {
            return Err(PatcherError::InsufficientPrivileges);
        }

        #[cfg(target_os = "windows")]
        {
            let command = "UsoClient.exe".to_string();
            let args = vec!["StartInstall".to_string()];
            let os_subsystem = "UsoClient".to_string();

            if dry_run {
                Ok(PatchExecutionResult {
                    dry_run: true,
                    command: command.clone(),
                    args: args.clone(),
                    success: true,
                    output: format!(
                        "[DRY-RUN] Planned execution: {} {}",
                        command,
                        args.join(" ")
                    ),
                    os_subsystem,
                })
            } else {
                let status = tokio::process::Command::new(&command)
                    .args(&args)
                    .output()
                    .await
                    .map_err(|e| PatcherError::ExecutionFailed(e.to_string()))?;
                let output = String::from_utf8_lossy(&status.stdout).to_string();
                Ok(PatchExecutionResult {
                    dry_run: false,
                    command,
                    args,
                    success: status.status.success(),
                    output,
                    os_subsystem,
                })
            }
        }

        #[cfg(target_os = "linux")]
        {
            let has_livepatch = std::path::Path::new("/usr/bin/canonical-livepatch").exists()
                || std::path::Path::new("/snap/bin/canonical-livepatch").exists();

            let (command, args, os_subsystem) = if has_livepatch {
                (
                    "canonical-livepatch".to_string(),
                    vec!["refresh".to_string()],
                    "canonical-livepatch".to_string(),
                )
            } else if std::path::Path::new("/usr/bin/apt-get").exists() {
                (
                    "apt-get".to_string(),
                    vec![
                        "upgrade".to_string(),
                        "-y".to_string(),
                        "linux-image-generic".to_string(),
                    ],
                    "apt-get".to_string(),
                )
            } else {
                (
                    "dnf".to_string(),
                    vec![
                        "upgrade".to_string(),
                        "--security".to_string(),
                        "-y".to_string(),
                        "kernel".to_string(),
                    ],
                    "dnf".to_string(),
                )
            };

            if dry_run {
                Ok(PatchExecutionResult {
                    dry_run: true,
                    command: command.clone(),
                    args: args.clone(),
                    success: true,
                    output: format!(
                        "[DRY-RUN] Planned execution: {} {}",
                        command,
                        args.join(" ")
                    ),
                    os_subsystem,
                })
            } else {
                let status = tokio::process::Command::new(&command)
                    .args(&args)
                    .output()
                    .await
                    .map_err(|e| PatcherError::ExecutionFailed(e.to_string()))?;
                let output = format!(
                    "{}{}",
                    String::from_utf8_lossy(&status.stdout),
                    String::from_utf8_lossy(&status.stderr)
                );
                Ok(PatchExecutionResult {
                    dry_run: false,
                    command,
                    args,
                    success: status.status.success(),
                    output,
                    os_subsystem,
                })
            }
        }

        #[cfg(target_os = "macos")]
        {
            let command = "softwareupdate".to_string();
            let args = vec!["--install".to_string(), "--recommended".to_string()];
            let os_subsystem = "softwareupdate".to_string();

            if dry_run {
                Ok(PatchExecutionResult {
                    dry_run: true,
                    command: command.clone(),
                    args: args.clone(),
                    success: true,
                    output: format!(
                        "[DRY-RUN] Planned execution: {} {}",
                        command,
                        args.join(" ")
                    ),
                    os_subsystem,
                })
            } else {
                let status = tokio::process::Command::new(&command)
                    .args(&args)
                    .output()
                    .await
                    .map_err(|e| PatcherError::ExecutionFailed(e.to_string()))?;
                let output = format!(
                    "{}{}",
                    String::from_utf8_lossy(&status.stdout),
                    String::from_utf8_lossy(&status.stderr)
                );
                Ok(PatchExecutionResult {
                    dry_run: false,
                    command,
                    args,
                    success: status.status.success(),
                    output,
                    os_subsystem,
                })
            }
        }

        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err(PatcherError::UnsupportedPlatform(
                std::env::consts::OS.to_string(),
            ))
        }
    }
}
