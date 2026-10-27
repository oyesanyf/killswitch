//! # Hardware CPU/Memory Watchdog & Cryptographic Heartbeat Challenge
//!
//! Provides:
//! 1. Periodic HMAC-SHA256 heartbeat challenge-response challenges (`KILL_CHALLENGE:nonce`)
//!    with constant-time verification (`subtle::ConstantTimeEq`).
//! 2. Missed heartbeat detection with structured watchdog alert emissions.
//! 3. Process working set memory trimming when memory budgets are exceeded.
//! 4. System memory pressure monitoring (`sysinfo`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use sysinfo::{Pid, System};

use killswitch_types::adjudication::EvidenceClass;
use killswitch_types::telemetry::{ThreatSeverity, ThreatSignal};

type HmacSha256 = Hmac<Sha256>;

/// Classification of host memory pressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MemoryPressureLevel {
    Normal,
    Warning,  // Available RAM < 600 MB
    Critical, // Available RAM < 250 MB
}

/// Hardware Watchdog configuration.
#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    pub heartbeat_interval: Duration,
    pub heartbeat_timeout: Duration,
    pub max_daemon_memory_mb: u64, // Default 250 MB
    pub warning_ram_threshold_mb: u64, // Default 600 MB
    pub critical_ram_threshold_mb: u64, // Default 250 MB
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: Duration::from_secs(5),
            heartbeat_timeout: Duration::from_secs(15),
            max_daemon_memory_mb: 250,
            warning_ram_threshold_mb: 600,
            critical_ram_threshold_mb: 250,
        }
    }
}

/// Cryptographic Hardware/Daemon Watchdog.
pub struct HardwareWatchdog {
    config: WatchdogConfig,
    secret_key: [u8; 32],
    last_challenge_nonce: AtomicU64,
    last_successful_heartbeat: parking_lot::RwLock<Instant>,
    consecutive_misses: AtomicU64,
}

impl HardwareWatchdog {
    pub const CHALLENGE_PREFIX: &'static [u8] = b"KILL_CHALLENGE:";

    pub fn new(secret_key: [u8; 32], config: WatchdogConfig) -> Self {
        Self {
            config,
            secret_key,
            last_challenge_nonce: AtomicU64::new(0),
            last_successful_heartbeat: parking_lot::RwLock::new(Instant::now()),
            consecutive_misses: AtomicU64::new(0),
        }
    }

    /// Issues a new unique 64-bit challenge nonce.
    pub fn issue_challenge(&self) -> u64 {
        let nonce = rand::random::<u64>();
        self.last_challenge_nonce.store(nonce, Ordering::SeqCst);
        nonce
    }

    /// Computes the correct HMAC-SHA256 response for a given challenge nonce.
    pub fn compute_expected_response(&self, nonce: u64) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.secret_key)
            .expect("HMAC-SHA256 initialization with 32-byte key is infallible");
        mac.update(Self::CHALLENGE_PREFIX);
        mac.update(&nonce.to_le_bytes());
        let result = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Verifies the challenge response in constant time using `subtle::ConstantTimeEq`.
    pub fn verify_heartbeat_response(&self, presented_response: &[u8]) -> bool {
        let current_nonce = self.last_challenge_nonce.load(Ordering::SeqCst);
        let expected = self.compute_expected_response(current_nonce);

        if presented_response.len() != expected.len() {
            self.consecutive_misses.fetch_add(1, Ordering::SeqCst);
            return false;
        }

        let is_valid: bool = expected.ct_eq(presented_response).into();
        if is_valid {
            *self.last_successful_heartbeat.write() = Instant::now();
            self.consecutive_misses.store(0, Ordering::SeqCst);
            true
        } else {
            self.consecutive_misses.fetch_add(1, Ordering::SeqCst);
            false
        }
    }

    /// Checks if the watchdog has timed out due to missed heartbeats.
    pub fn check_liveness(&self) -> Option<ThreatSignal> {
        let elapsed = self.last_successful_heartbeat.read().elapsed();
        if elapsed > self.config.heartbeat_timeout {
            let misses = self.consecutive_misses.load(Ordering::SeqCst);
            let mut sig = ThreatSignal::new(
                "hardware-watchdog",
                std::process::id(),
                "daemon_watchdog",
                0.95,
                ThreatSeverity::Critical,
                EvidenceClass::Behavior,
                format!(
                    "Watchdog heartbeat lost: no response for {:.2?} (timeout: {:.2?}, misses: {})",
                    elapsed, self.config.heartbeat_timeout, misses
                ),
            );

            sig.raw_evidence = serde_json::json!({
                "elapsed_ms": elapsed.as_millis(),
                "consecutive_misses": misses,
                "timeout_ms": self.config.heartbeat_timeout.as_millis(),
            });

            Some(sig)
        } else {
            None
        }
    }

    /// Evaluates current system memory and trims working set if daemon RSS exceeds budget.
    pub fn audit_memory_and_trim(&self) -> MemoryPressureLevel {
        let mut sys = System::new_all();
        sys.refresh_memory();
        sys.refresh_processes();

        let available_ram_mb = sys.available_memory() / (1024 * 1024);

        // Check daemon process RSS
        let my_pid = Pid::from_u32(std::process::id());
        if let Some(proc) = sys.process(my_pid) {
            let rss_mb = proc.memory() / (1024 * 1024);
            if rss_mb > self.config.max_daemon_memory_mb {
                Self::trim_process_working_set();
            }
        }

        if available_ram_mb < self.config.critical_ram_threshold_mb {
            Self::trim_process_working_set();
            MemoryPressureLevel::Critical
        } else if available_ram_mb < self.config.warning_ram_threshold_mb {
            Self::trim_process_working_set();
            MemoryPressureLevel::Warning
        } else {
            MemoryPressureLevel::Normal
        }
    }

    /// Cross-platform process working set empty / memory trim.
    pub fn trim_process_working_set() {
        #[cfg(windows)]
        {
            use windows::Win32::System::Threading::{GetCurrentProcess, SetProcessWorkingSetSize};
            unsafe {
                let _ = SetProcessWorkingSetSize(GetCurrentProcess(), usize::MAX, usize::MAX);
            }
        }

        #[cfg(target_os = "linux")]
        {
            extern "C" {
                fn malloc_trim(pad: usize) -> i32;
            }
            unsafe {
                malloc_trim(0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watchdog_hmac_challenge_response_cycle() {
        let key = [0x42u8; 32];
        let watchdog = HardwareWatchdog::new(key, WatchdogConfig::default());

        let nonce = watchdog.issue_challenge();
        let expected = watchdog.compute_expected_response(nonce);

        // Valid response succeeds in constant time
        assert!(watchdog.verify_heartbeat_response(&expected));
        assert!(watchdog.check_liveness().is_none());

        // Tampered response fails
        let mut tampered = expected;
        tampered[0] ^= 0xFF;
        assert!(!watchdog.verify_heartbeat_response(&tampered));
    }

    #[test]
    fn test_watchdog_timeout_alert_generation() {
        let key = [0x77u8; 32];
        let config = WatchdogConfig {
            heartbeat_interval: Duration::from_millis(5),
            heartbeat_timeout: Duration::from_millis(10),
            ..Default::default()
        };
        let watchdog = HardwareWatchdog::new(key, config);

        // Simulate elapsed time
        std::thread::sleep(Duration::from_millis(15));
        let alert = watchdog.check_liveness();
        assert!(alert.is_some());
        let sig = alert.unwrap();
        assert_eq!(sig.source_detector, "hardware-watchdog");
        assert_eq!(sig.severity, ThreatSeverity::Critical);
    }
}
