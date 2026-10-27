//! # KillSwitch CLI & Unified Loader Library
//!
//! Provides the command line interfaces, direct control client, subsystem self-verifier,
//! and unified loader runtime for `killswitch` and `start.exe`.

pub mod client;
pub mod commands;
pub mod loader;
pub mod verify;

pub use client::KillSwitchClient;
pub use loader::{UnifiedConfig, UnifiedRuntime};
pub use verify::{PhaseReport, SubsystemVerifier, VerificationReport};
