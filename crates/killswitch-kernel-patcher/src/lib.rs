//! `killswitch-kernel-patcher`: NVD API 2.0 / CISA KEV kernel vulnerability scanner and OS-native patch orchestrator.

pub mod cpe;
pub mod discovery;
pub mod error;
pub mod patcher;
pub mod privilege;
pub mod types;

// Re-exports
pub use cpe::Cpe23;
pub use error::PatcherError;
pub use patcher::KernelPatcher;
pub use privilege::is_elevated;
pub use types::{HostKernelInfo, KernelVulnerability, OsFamily, PatchExecutionResult, ScanOptions};
