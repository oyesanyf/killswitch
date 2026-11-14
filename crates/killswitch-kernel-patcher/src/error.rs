//! Error types for `killswitch-kernel-patcher`.

use thiserror::Error;

/// Error taxonomy for the `killswitch-kernel-patcher` crate.
#[derive(Debug, Error)]
pub enum PatcherError {
    #[error("Insufficient privileges: kernel patch execution requires root/Administrator")]
    InsufficientPrivileges,

    #[error("Unsupported platform: {0}")]
    UnsupportedPlatform(String),

    #[error("Kernel detection failed: {0}")]
    DetectionFailed(String),

    #[error("NVD API error: {0}")]
    NvdApiError(String),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Command execution error: {0}")]
    ExecutionFailed(String),

    #[error("Rate limited by NVD API")]
    RateLimited,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
