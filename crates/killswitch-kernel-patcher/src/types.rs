//! Core type definitions for `killswitch-kernel-patcher`.

use crate::error::PatcherError;
use serde::{Deserialize, Serialize};

/// Operating system platform family detected on the host.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OsFamily {
    Linux,
    Windows,
    MacOS,
    Unknown(String),
}

impl OsFamily {
    #[inline]
    #[must_use]
    pub fn is_linux(&self) -> bool {
        matches!(self, Self::Linux)
    }

    #[inline]
    #[must_use]
    pub fn is_windows(&self) -> bool {
        matches!(self, Self::Windows)
    }

    #[inline]
    #[must_use]
    pub fn is_macos(&self) -> bool {
        matches!(self, Self::MacOS)
    }
}

impl std::fmt::Display for OsFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Linux => write!(f, "Linux"),
            Self::Windows => write!(f, "Windows"),
            Self::MacOS => write!(f, "macOS"),
            Self::Unknown(name) => write!(f, "Unknown ({name})"),
        }
    }
}

/// Host operating system and kernel version discovery metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostKernelInfo {
    /// Operating system platform family.
    pub os_family: OsFamily,
    /// Kernel release version (e.g. "6.8.0-45-generic", "10.0.22631.3880", "23.4.0").
    pub kernel_release: String,
    /// User-facing OS version (e.g. "24.04", "Windows 11 23H2", "14.4.1").
    pub os_version: String,
    /// NIST Common Platform Enumeration 2.3 formatted identifier.
    pub cpe23: String,
    /// Target hardware CPU architecture (e.g. "x86_64", "aarch64").
    pub architecture: String,
}

impl HostKernelInfo {
    /// Probes the host system and constructs verified `HostKernelInfo`.
    pub fn detect_host_kernel() -> Result<Self, PatcherError> {
        crate::discovery::detect_host_kernel()
    }

    /// Returns the CPE 2.3 formatted string.
    #[inline]
    #[must_use]
    pub fn to_cpe23(&self) -> String {
        self.cpe23.clone()
    }
}

/// Kernel vulnerability record parsed from NVD API 2.0 / CISA KEV catalog.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KernelVulnerability {
    /// Common Vulnerabilities and Exposures (CVE) identifier (e.g. "CVE-2024-21338").
    pub cve_id: String,
    /// Primary vulnerability description.
    pub description: String,
    /// CVSS v3.1 base score if scored (0.0 - 10.0).
    pub cvss_v31_score: Option<f32>,
    /// CVSS v3.1 qualitative severity rating ("LOW", "MEDIUM", "HIGH", "CRITICAL").
    pub cvss_v31_severity: Option<String>,
    /// Whether this vulnerability is listed in the CISA Known Exploited Vulnerabilities catalog.
    pub is_cisa_kev: bool,
    /// Date added to the CISA KEV catalog (YYYY-MM-DD).
    pub cisa_exploit_add: Option<String>,
    /// Remediation due date mandated by CISA BOD 22-01.
    pub cisa_action_due: Option<String>,
    /// Required remediation action specified by CISA.
    pub cisa_required_action: Option<String>,
    /// Descriptive vulnerability name from CISA KEV.
    pub cisa_vulnerability_name: Option<String>,
}

/// Options configuring the NVD vulnerability scan.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Target CPE 2.3 string (defaults to auto-detected host kernel CPE).
    pub cpe: Option<String>,
    /// Minimum CVSS score threshold for returned findings (inclusive).
    pub min_cvss_score: Option<f32>,
    /// If true, only return vulnerabilities confirmed in the CISA KEV catalog.
    pub kev_only: bool,
    /// Optional NVD API key (resolved from `std::env::var("NVD_API_KEY")`, never CLI arguments).
    pub api_key: Option<String>,
    /// HTTP request timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            cpe: None,
            min_cvss_score: None,
            kev_only: false,
            api_key: None,
            timeout_secs: 30,
        }
    }
}

/// Result of an OS-native kernel patch execution or dry-run evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchExecutionResult {
    /// True if executed in safe simulation mode with zero system modifications.
    pub dry_run: bool,
    /// Primary executable command that was or would be invoked.
    pub command: String,
    /// Command-line arguments.
    pub args: Vec<String>,
    /// Whether the process exited successfully (exit code 0).
    pub success: bool,
    /// Combined stdout and stderr output.
    pub output: String,
    /// Subsystem identifier (e.g. "canonical-livepatch", "apt", "dnf", "UsoClient", "softwareupdate").
    pub os_subsystem: String,
}
