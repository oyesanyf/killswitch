//! Cross-platform native OS service configuration, status, and error types.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

/// Operational state of a native OS service daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    /// Service is actively running and processing events.
    Running,
    /// Service is stopped.
    Stopped,
    /// Service is in transition to running.
    StartPending,
    /// Service is in transition to stopped.
    StopPending,
    /// Service is paused.
    Paused,
    /// Service is installed but state is undetermined.
    Unknown,
    /// Service is not registered/installed on the host.
    NotInstalled,
}

impl std::fmt::Display for ServiceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceState::Running => write!(f, "running"),
            ServiceState::Stopped => write!(f, "stopped"),
            ServiceState::StartPending => write!(f, "start_pending"),
            ServiceState::StopPending => write!(f, "stop_pending"),
            ServiceState::Paused => write!(f, "paused"),
            ServiceState::Unknown => write!(f, "unknown"),
            ServiceState::NotInstalled => write!(f, "not_installed"),
        }
    }
}

/// Comprehensive status report for a native OS service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceStatus {
    /// Canonical identifier / service name (e.g., "killswitch" or "com.oshoosi.killswitch").
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Current operational state.
    pub state: ServiceState,
    /// Process ID if the service is currently running.
    pub pid: Option<u32>,
    /// Path to the service binary on disk.
    pub binary_path: Option<String>,
    /// Service description string.
    pub description: Option<String>,
    /// True if the service unit / registry / plist exists on the system.
    pub is_installed: bool,
}

impl ServiceStatus {
    pub fn not_installed(name: impl Into<String>) -> Self {
        let name_str = name.into();
        Self {
            display_name: name_str.clone(),
            name: name_str,
            state: ServiceState::NotInstalled,
            pid: None,
            binary_path: None,
            description: None,
            is_installed: false,
        }
    }

    pub fn running(
        name: impl Into<String>,
        display_name: impl Into<String>,
        pid: u32,
        binary_path: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            display_name: display_name.into(),
            state: ServiceState::Running,
            pid: Some(pid),
            binary_path,
            description: None,
            is_installed: true,
        }
    }

    pub fn stopped(
        name: impl Into<String>,
        display_name: impl Into<String>,
        binary_path: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            display_name: display_name.into(),
            state: ServiceState::Stopped,
            pid: None,
            binary_path,
            description: None,
            is_installed: true,
        }
    }
}

/// Specification for installing and configuring a native OS service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Canonical service name (e.g. "killswitch" on Win/Linux, "com.oshoosi.killswitch" on macOS).
    pub name: String,
    /// Human-readable display name (e.g. "KillSwitch Security Agent").
    pub display_name: String,
    /// Service description text.
    pub description: String,
    /// Absolute path to executable.
    pub executable_path: PathBuf,
    /// Startup command-line arguments.
    pub arguments: Vec<String>,
    /// Optional working directory.
    pub working_dir: Option<PathBuf>,
    /// Whether the service should automatically start on host boot.
    pub auto_start: bool,
    /// Configurable root directory override for testing filesystem-based installers (systemd/launchd).
    pub root_dir: Option<PathBuf>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("killswitch"));
        Self {
            name: "killswitch".to_string(),
            display_name: "KillSwitch Security Agent".to_string(),
            description: "Native zero-OS-tool host containment and security daemon".to_string(),
            executable_path: exe,
            arguments: vec!["service".to_string(), "run".to_string()],
            working_dir: None,
            auto_start: true,
            root_dir: None,
        }
    }
}

/// Dedicated error enumeration for native OS service lifecycle operations.
#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("Service '{0}' is already installed")]
    AlreadyInstalled(String),

    #[error("Service '{0}' is not installed")]
    NotFound(String),

    #[error("Failed to install service '{0}': {1}")]
    InstallFailed(String, String),

    #[error("Failed to uninstall service '{0}': {1}")]
    UninstallFailed(String, String),

    #[error("Failed to start service '{0}': {1}")]
    StartFailed(String, String),

    #[error("Failed to stop service '{0}': {1}")]
    StopFailed(String, String),

    #[error("Failed to query status of service '{0}': {1}")]
    QueryFailed(String, String),

    #[error("Service daemon error: {0}")]
    DaemonError(String),

    #[error("Insufficient permissions for service management: {0}")]
    PermissionDenied(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("System error: {0}")]
    System(String),
}
